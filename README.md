# blst-z
Zig wrapper for [supranational/blst](https://github.com/supranational/blst) native bindings, a highly performant BLS12-381 signature library.

# How to build
- clone hashtree to root: `git clone --recurse-submodules https://github.com/supranational/blst.git`
- `zig build`
- locate `zig-out/lib/libhashtree-z.dylib` (could be diffrerent name in other OSs) and continue the test below
