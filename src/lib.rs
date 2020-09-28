#![no_std]

use libc::{c_int, c_void, siginfo_t, size_t};
use mersenne_twister::MersenneTwister;
use rand::{Rng, SeedableRng};

use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

struct RmallocInner {
    pub rng: MersenneTwister,
    pub probe_fail: bool,
}

struct RmallocState {
    // 0: uninitialized
    // 1: initializing
    // 2: initialized
    initializing: AtomicU8,
    mallocating: AtomicBool,
    state: UnsafeCell<MaybeUninit<RmallocInner>>,
}

// safety: my brain said so
unsafe impl Sync for RmallocState {}

impl RmallocState {
    const fn new() -> Self {
        RmallocState {
            initializing: AtomicU8::new(0),
            mallocating: AtomicBool::new(false),
            state: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn init(&self) {
        let init_state = self.initializing.compare_and_swap(0, 1, Ordering::SeqCst);
        if init_state == 2 {
            return;
        } else if init_state == 0 {
            // just set from uninitialized->initializing, actually initialize
            let rng: MersenneTwister = SeedableRng::from_seed(0xaaaA_aaAA_aaaA_aaAa);
            let inner = RmallocInner {
                rng,
                probe_fail: false,
            };
            let mut segv_handler_mask = SigSet::empty();
            segv_handler_mask.add(Signal::SIGBUS);
            segv_handler_mask.add(Signal::SIGSEGV);
            let sa = SigAction::new(
                SigHandler::SigAction(handle_segv),
                SaFlags::SA_RESTART | SaFlags::SA_SIGINFO,
                segv_handler_mask,
            );
            unsafe {
                let _sigsegv = sigaction(Signal::SIGSEGV, &sa).expect("can set sigsegv handler");
                let _sigbus = sigaction(Signal::SIGBUS, &sa).expect("can set sigbus handler");
                core::ptr::write(self.state.get().as_mut().unwrap().as_mut_ptr(), inner);
            }
            self.initializing.store(2, Ordering::SeqCst);
        } else {
            // init_state == 1, and is currently being initialized. spin while that's in progress.
            loop {
                if self.initializing.load(Ordering::SeqCst) == 2 {
                    break;
                }
            }
        }
    }

    fn mallocate(&self, page_count: usize) -> *mut c_void {
        let _guard = self.begin_mallocate();

        loop {
            // lol
            let guess = unsafe {
                self.state
                    .get()
                    .as_mut()
                    .unwrap()
                    .as_mut_ptr()
                    .as_mut()
                    .unwrap()
                    .rng
                    .next_u64() as usize
            };
            let page_address = (guess.wrapping_mul(PAGE_SIZE)) & 0x0000_ffff_ffff_ffff;
            if page_address.checked_add(page_count * PAGE_SIZE).is_none() {
                // can't satisfy this request, it'll overflow. try again.
                continue;
            }

            let mut probe_failed = false;
            for i in 0..page_count {
                if !self.probe_page(page_address + (i * PAGE_SIZE)) {
                    probe_failed = true;
                    break;
                }
            }

            if probe_failed {
                // one or more pages is not available. give up and try again.
                continue;
            }

            // if we get a pointer, we're all done yay
            return unsafe {
                mmap(
                    page_address as *mut c_void,
                    page_count * PAGE_SIZE,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE,
                    -1,
                    0,
                )
                .expect("can mmap")
            };
        }
    }

    fn probe_page(&self, page_addr: usize) -> bool {
        unsafe {
            let ptr = (page_addr as *mut AtomicU8).as_ref().unwrap();
            // we don't know if we've failed the probe *yet*
            self.state
                .get()
                .as_mut()
                .unwrap()
                .as_mut_ptr()
                .as_mut()
                .unwrap()
                .probe_fail = false;
            // do the probe. this is a read and a write
            ptr.fetch_xor(0, Ordering::SeqCst);
            // if the probe failed, it's possible this page is r-- and otherwise already allocated. try
            // again to confirm we can't read from it at all.
            if self
                .state
                .get()
                .as_mut()
                .unwrap()
                .as_mut_ptr()
                .as_mut()
                .unwrap()
                .probe_fail
            {
                self.state
                    .get()
                    .as_mut()
                    .unwrap()
                    .as_mut_ptr()
                    .as_mut()
                    .unwrap()
                    .probe_fail = false;
                ptr.load(Ordering::SeqCst);
            }

            !self
                .state
                .get()
                .as_mut()
                .unwrap()
                .as_mut_ptr()
                .as_mut()
                .unwrap()
                .probe_fail
        }
    }

    fn begin_mallocate(&self) -> MallocGuard {
        loop {
            // if we can update `mallocating` from `false` to `true`, we have established
            // exclusivity for mallocation and can proceed. otherwise, try, try again.
            if !self.mallocating.swap(true, Ordering::SeqCst) {
                break;
            }
        }

        MallocGuard::of(self)
    }
}

struct MallocGuard<'a> {
    state: &'a RmallocState,
}

impl<'a> MallocGuard<'a> {
    fn of(state: &'a RmallocState) -> Self {
        MallocGuard { state }
    }
}

impl<'a> Drop for MallocGuard<'a> {
    fn drop(&mut self) {
        assert!(self.state.mallocating.load(Ordering::SeqCst));
        self.state.mallocating.store(false, Ordering::SeqCst);
    }
}

pub extern "C" fn handle_segv(
    _signum: c_int,
    _siginfo_ptr: *mut siginfo_t,
    _ucontext_ptr: *mut c_void,
) {
    // ignore _signum: this is only installed for sigsegv and sigbus, both of whom we want to
    // handle
    //
    // TODO: check that the fault address is where a probe would have been done
    if RMALLOC_STATE.mallocating.load(Ordering::SeqCst) {
        // faulted while mallocating. if the fault was due to a probe, cool, the page is available
        // and we can try mmaping later maybe. if this fault was coincidental while another thread
        // is in malloc, well, i may just have hid a sigsegv.
        //
        // if so, rip 2 your address space but i'm different.
        //
        // safety: malloc enforces exclusivity over access to .state, and there isn't a live ref
        // when the probe is done.
        unsafe {
            RMALLOC_STATE
                .state
                .get()
                .as_mut()
                .unwrap()
                .as_mut_ptr()
                .as_mut()
                .unwrap()
                .probe_fail = true;
        }
    } else {
        // spurious malloc, ouch
        // TODO: something
        // std::process::exit(signum);
    }
}

#[repr(C)]
struct AllocMetadata {
    page_count: u32, // if you want to malloc more than 2^32*2^10 == 2^42 bytes, this is not the malloc for you. that's 4 petabytes.
    _padding: [u8; 60], // pad out to 64 bytes because that should be enough
}

static RMALLOC_STATE: RmallocState = RmallocState::new();

// hugepages? never heard of em
const PAGE_SIZE: usize = 4096;

#[no_mangle]
pub extern "C" fn malloc(sz: size_t) -> *mut c_void {
    // if rmalloc is already initialized this'll be fast
    RMALLOC_STATE.init();
    let total_alloc_min = sz + core::mem::size_of::<AllocMetadata>();
    let page_rounded_size = (total_alloc_min + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let page_count = page_rounded_size >> (10 + 2);
    assert!(page_count != 0);
    let ptr = RMALLOC_STATE.mallocate(page_count);
    unsafe {
        core::ptr::write(
            ptr as *mut AllocMetadata,
            AllocMetadata {
                page_count: page_count as u32,
                _padding: [0; 60],
            },
        );
    }
    (ptr as usize + core::mem::size_of::<AllocMetadata>()) as *mut c_void
}

#[no_mangle]
pub extern "C" fn calloc(nmemb: size_t, size: size_t) -> *mut c_void {
    let total_size = nmemb.wrapping_mul(size);
    let ptr = malloc(total_size);

    for i in 0..total_size {
        unsafe {
            *((ptr as *mut u8).offset(i as isize)) = 0;
        }
    }

    ptr
}

#[no_mangle]
pub extern "C" fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void {
    let new_region = malloc(size);

    if new_region == core::ptr::null_mut() {
        return new_region;
    }

    if ptr == core::ptr::null_mut() {
        return new_region;
    }

    let alloc_metadata =
        (ptr as usize - core::mem::size_of::<AllocMetadata>()) as *mut AllocMetadata;
    let old_page_count = unsafe { alloc_metadata.as_ref().unwrap().page_count as usize };
    let old_sz = old_page_count * PAGE_SIZE - core::mem::size_of::<AllocMetadata>();

    let copy_sz = core::cmp::min(old_sz, size);

    for i in 0..copy_sz {
        unsafe {
            *(new_region as *mut u8).offset(i as isize) = *(ptr as *mut u8).offset(i as isize);
        }
    }

    new_region
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut c_void) {
    if ptr == core::ptr::null_mut() {
        return;
    }

    let alloc_metadata =
        (ptr as usize - core::mem::size_of::<AllocMetadata>()) as *mut AllocMetadata;
    unsafe {
        let page_count = alloc_metadata.as_ref().unwrap().page_count as usize;
        munmap(
            alloc_metadata as *mut c_void,
            page_count.wrapping_mul(PAGE_SIZE),
        )
        .unwrap();
    }
}
