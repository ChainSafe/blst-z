import {type Pointer, read} from "bun:ffi";
import {MAX_AGGREGATE_PER_JOB, PUBLIC_KEY_SIZE, SIGNATURE_LENGTH} from "./const.js";
import type {PublicKey} from "./publicKey.js";
import type {Signature} from "./signature.js";

/**
 * Write a pointer value to a buffer at the specified offset.
 * NOTE: Only works with pointers of size divisible by 4.
 */
function writePtr(ptr: Pointer, size: number, buf: Uint32Array, offset: number): void {
	for (let i = 0; i < size / 4; i++) {
		buf[offset + i] = read.u32(ptr, i * 4);
	}
}

// Operations involving multiple pks require pks in contiguous memory.
// This buffer is (re)used for this purpose.
const pksBuffer = new ArrayBuffer(PUBLIC_KEY_SIZE * MAX_AGGREGATE_PER_JOB);
const sigsBuffer = new ArrayBuffer(SIGNATURE_LENGTH * MAX_AGGREGATE_PER_JOB);
export const pksU8 = new Uint8Array(pksBuffer);
const pksU32 = new Uint32Array(pksBuffer);
export const sigsU8 = new Uint8Array(sigsBuffer);

export function writePublicKeys(pks: PublicKey[]): void {
	for (const [i, pk] of pks.entries()) {
		writePublicKey(pk, i);
	}
}

function writePublicKey(pk: PublicKey, i: number): void {
	if (typeof pk.ptr === "number") {
		writePtr(pk.ptr, PUBLIC_KEY_SIZE, pksU32, (i * PUBLIC_KEY_SIZE) / 4);
	} else {
		pksU8.set(pk.ptr, i * PUBLIC_KEY_SIZE);
	}
}

export function writeSignatures(sigs: Signature[]): void {
	for (const [i, sig] of sigs.entries()) {
		writeSignature(sig, i);
	}
}

function writeSignature(sig: Signature, i: number): void {
	sigsU8.set(sig.ptr, i * SIGNATURE_LENGTH);
}

// Operations involving multiple msgs require msgs in contiguous memory.
const msgsBuffer = new ArrayBuffer(32 * MAX_AGGREGATE_PER_JOB);
export const msgsU8 = new Uint8Array(msgsBuffer);

export function writeMessages(msgs: Uint8Array[]): void {
	for (const [i, msg] of msgs.entries()) {
		msgsU8.set(msg, i * 32);
	}
}
