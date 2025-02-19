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

  // TODO: check endianess, this is for little endian
  out[offset] = pointer & 0xFFFFFFFF;
  out[offset + 1] = Math.floor(pointer / Math.pow(2, 32));
}
