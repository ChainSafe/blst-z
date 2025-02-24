import {dlopen, ptr} from "bun:ffi";
import { getBinaryName, getPrebuiltBinaryPath } from "../utils";

// const binaryName = getBinaryName();
// const binaryPath = getPrebuiltBinaryPath(binaryName);

const binaryPath = "/Users/tuyennguyen/Projects/workshop/blst-z/zig-out/lib/libblst_min_pk.dylib";

// Load the compiled Zig shared library
const lib = dlopen(binaryPath, {
  // PublicKey functions
  validatePublicKey: {
    args: ["ptr"],
    returns: "u8"
  },
  publicKeyBytesValidate: {
    args: ["ptr", "u64"],
    returns: "u8"
  },
  publicKeyFromAggregate: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  compressPublicKey: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  serializePublicKey: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  uncompressPublicKey: {
    args: ["ptr", "ptr", "u64"],
    returns: "void"
  },
  deserializePublicKey: {
    args: ["ptr", "ptr", "u64"],
    returns: "u8"
  },
  toPublicKeyBytes: {
    args: ["ptr", "ptr"],
    returns: "void"
  },
  isPublicKeyEqual: {
    args: ["ptr", "ptr"],
    returns: "bool"
  },
  // SecretKey functions
  secretKeyGen: {
    args: ["ptr", "ptr", "u32", "ptr", "u32"],
    returns: "u8",
  },
  secretKeyDeriveMasterEip2333: {
    args: ["ptr", "ptr", "u32"],
    returns: "u8",
  },
  secretKeyDeriveChildEip2333: {
    args: ["ptr", "ptr", "u32"],
    returns: "void",
  },
  secretKeyFromBytes: {
    args: ["ptr", "ptr", "u32"],
    returns: "u8",
  },
  secretKeyToBytes: {
    args: ["ptr", "ptr"],
    returns: "void",
  },
  secretKeyToPublicKey: {
    args: ["ptr", "ptr"],
    returns: "void",
  },
  sign: {
    args: ["ptr", "ptr", "ptr", "u32"],
    returns: "void",
  },
  // Signature functions
  signatureFromBytes: {
    args: ["ptr", "ptr", "u32"],
    returns: "u8",
  },
  sigValidate: {
    args: ["ptr", "ptr", "u32", "bool"],
    returns: "u8",
  },
  signatureToBytes: {
    args: ["ptr", "ptr"],
    returns: "void",
  },
  serializeSignature: {
    args: ["ptr", "ptr"],
    returns: "void",
  },
  validateSignature: {
    args: ["ptr", "bool"],
    returns: "u8",
  },
  verifySignature: {
    args: ["ptr", "bool", "ptr", "u32", "ptr", "bool"],
    returns: "u8",
  },
  aggregateVerify: {
    args: ["ptr", "bool", "ptr", "u32", "u32", "ptr", "u32", "bool", "ptr", "u32"],
    returns: "u8",
  },
  fastAggregateVerify: {
    args: ["ptr", "bool", "ptr", "u32", "ptr", "u32", "ptr", "u32"],
    returns: "u8",
  },
  verifyMultipleAggregateSignatures: {
    args: ["ptr", "u32", "u32", "bool", "bool", "ptr", "u32"],
    returns: "u32",
  },
  sizeOfPairing: {
    args: [],
    returns: "u32",
  },
  aggregatePublicKeys: {
    args: ["ptr", "ptr", "u32", "bool"],
    returns: "u32",
  },
  aggregateSignatures: {
    args: ["ptr", "ptr", "u32", "bool"],
    returns: "u32",
  },
  aggregateWithRandomness: {
    args: ["ptr", "u32", "ptr", "u32", "ptr", "u32", "ptr", "ptr"],
    returns: "u32",
  },
  asyncAggregateWithRandomness: {
    args: ["ptr", "u32", "ptr", "u32", "ptr", "u32", "ptr", "ptr", "callback"],
    // TODO: may return void instead
    returns: "u32",
  },
  aggregateSerializedPublicKeys: {
    args: ["ptr", "ptr", "u32", "u32", "bool"],
    returns: "u32",
  },
  aggregateSerializedSignatures: {
    args: ["ptr", "ptr", "u32", "u32", "bool"],
    returns: "u32",
  },
  sizeOfScratchPk: {
    args: ["u32"],
    returns: "u32",
  },
  sizeOfScratchSig: {
    args: ["u32"],
    returns: "u32",
  }
});

export const binding = lib.symbols;

export function closeBinding(): void {
  lib.close();
}

/**
 * Write reference of a data to the provided Uint32Array at offset
 * TODO: may accept data + offset and compute pointer from the parent typed array. This will help to avoid `subarray()` calls.
 */
export function writeReference(data: Uint8Array | Uint32Array, out: Uint32Array, offset: number): void {
  // 2 items of uint32 means 8 of uint8
  if (offset + 2 > out.length) {
    throw new Error("Output buffer must be at least 8 bytes long");
  }

  const pointer = ptr(data);

  writeNumber(pointer, out, offset);
}

/**
 * Write a number to "usize" in Zig, which takes 8 bytes
 */
export function writeNumber(data: number, out: Uint32Array, offset: number): void {
  if (offset + 2 > out.length) {
    throw new Error("Output buffer must be at least 8 bytes long");
  }

  // TODO: check endianess, this is for little endian
  out[offset] = data & 0xFFFFFFFF;
  out[offset + 1] = Math.floor(data / Math.pow(2, 32));
}

/**
 * Common util to map Uint8Array[] to `[*c][*c]const u8` in Zig
 */
export function writeUint8ArrayArray(data: Uint8Array[], maxItem: number, tag: string, out: Uint32Array): void {
  if (data.length > maxItem) {
    throw new Error(`Too many ${tag}s, max is ${maxItem}`);
  }

  if (out.length < data.length * 2) {
    throw new Error(`Output buffer must be at least double data size. out: ${out.length}, data: ${data.length}`);
  }

  const pk_length = data[0].length;

  for (let i = 0; i < data.length; i++) {
    if (data[i].length !== pk_length) {
      throw new Error(`All ${tag}s must be the same length`);
    }
    writeReference(data[i], out, i * 2);
  }
}