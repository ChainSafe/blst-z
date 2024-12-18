# blst-z
Zig wrapper for [supranational/blst](https://github.com/supranational/blst) native bindings, a highly performant BLS12-381 signature library.

## Installation
- clone blst to root: `git clone --recurse-submodules https://github.com/supranational/blst.git`
- `zig build test`

## Usage
The below shows how to use min_pk namespace

```zig
pub const min_pk = @import("blst").min_pk;
const SecretKey = min_pk.SecretKey;
const ikm: [32]u8 = [_]u8{
    0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
    0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
    0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
    0x48, 0x99,
};
const sk = try SecretKey.keyGen(ikm[0..], null);
const pk = sk.skToPk();

const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const msg = "hello foo";
// aug is null
const sig = sk.sign(msg[0..], dst[0..], null);

// aug is null
try sig.verify(true, msg[0..], dst[0..], null, &pk, true);
```