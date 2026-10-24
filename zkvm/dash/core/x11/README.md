Vendored from dashpay/rs-x11-hash at f2ca8a736530d03943e6b4b8656d2736906ae7fe (MIT, see LICENSE):
`x11_hash.c`, `x11_hash.h`, `x11/*.h` (the sph reference implementations of the eleven X11 functions)
and `sysroot/` (the minimal libc headers that crate ships for freestanding wasm builds, reused here for
the SP1 RISC-V target). Unmodified.
