import {type Pointer, ptr, read} from "bun:ffi";
import type {PublicKey} from "./publicKey.js";
import type {Signature} from "./signature.js";

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
	out[offset] = data & 0xffffffff;
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

	const pkLength = data[0].length;

	for (let i = 0; i < data.length; i++) {
		if (data[i].length !== pkLength) {
			throw new Error(`All ${tag}s must be the same length`);
		}
		writeReference(data[i], out, i * 2);
	}
}
/**
 * Write a pointer value to a buffer at the specified offset.
 * NOTE: Only works with pointers of size divisible by 4.
 */
export function writePtr(ptr: Pointer, size: number, buf: Uint32Array, offset: number): void {
	for (let i = 0; i < size / 4; i++) {
		buf[offset + i] = read.u32(ptr, i * 4);
	}
}

const MAX_PKS = 128;
// global public key references to be reused across multiple calls
const publicKeysRefs = new Uint32Array(MAX_PKS * 2);

/**
 * Map PublicKey[] in typescript to [*c]const *PublicKeyType in Zig.
 */
export function writePublicKeysReference(pks: PublicKey[]): Uint32Array {
	if (pks.length > MAX_PKS) {
		throw new Error(`Too many public keys, max is ${MAX_PKS}`);
	}

	for (let i = 0; i < pks.length; i++) {
		writeReference(pks[i].ptr, publicKeysRefs, i * 2);
	}

	return publicKeysRefs.subarray(0, pks.length * 2);
}

// global public key references to be reused across multiple calls
const signaturesRefs = new Uint32Array(MAX_PKS * 2);

/**
 * Map Signature[] in typescript to [*c]const *SignatureType in Zig.
 */
export function writeSignaturesReference(sigs: Signature[]): Uint32Array {
	if (sigs.length > MAX_PKS) {
		throw new Error(`Too many signatures, max is ${MAX_PKS}`);
	}

	for (let i = 0; i < sigs.length; i++) {
		writeReference(sigs[i].ptr, signaturesRefs, i * 2);
	}

	return signaturesRefs.subarray(0, sigs.length * 2);
}
