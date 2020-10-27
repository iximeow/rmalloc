## `rmalloc`

> what's the point of an address space this large if we don't use chunks of it randomly
* a wise software engineer

`rmalloc` is a `malloc` (and `calloc`, and `realloc`, and, of course, `free`)
implementation that improves upon traditional `malloc` implementations by
taking advantage of the size of modern processor address spaces to provide
cryptographically enhanced security in allocations.

#### usage

`rmalloc` is most easily used with a simple `LD_PRELOAD` - first, get the repo,
then run the program you want to secure like normal, but with
`LD_PRELOAD=path/to/librmalloc.so` in front of it. for example:
```
LD_PRELOAD=./target/release/librmalloc.so cargo build
```
in the `rmalloc` repo should .. almost .. complete without error.

### "help, my program reports that it crashed with `Segmentation fault`!!!!!"

it probably caught the segfault rmalloc uses to probe if a page can be used for
a new allocation, and thought the fault was due to its own behavior. `vim` and
`collect2` both do this. some applications do not chain signal handlers on the
assumption they have exclusive interest in signals or signal handling, so
naively overwriting the `SIGSEGV` handler will irreparably break `rmalloc`.

#### theory

at its core, `rmalloc` uses the Mersenne Twister algorithm to randomly select
addresses for allocations. it will then probe to see if the chosen address has
been allocated, and if not, will then allocate it with a high-performance
`mmap` system call. because the `mmap` function is implemented inside the Linux
kernel, it is secure to RCE exploits and supply chain (software update)
attacks. because it is in the krenel, it is also fast.

#### thread safety

`rmalloc` is thread safe.

#### `no_std`

`rmalloc` is `no_std`. it is appropriate for embedded usage to replace glibc or other `malloc`.

#### the name `rmalloc`

this is a joke crate. if you'd like the name for pretty much any more serious purpose feel free to email me.
