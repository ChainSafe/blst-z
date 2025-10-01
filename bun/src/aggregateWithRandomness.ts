import {JSCallback} from "bun:ffi";
import {binding} from "./binding.js";
import {pksU8, writePublicKeys} from "./buffer.ts";
import {MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB, PUBLIC_KEY_SIZE, SIGNATURE_LENGTH} from "./const.js";
import {PublicKey} from "./publicKey.js";
import {Signature} from "./signature.js";
import {writeNumber, writePublicKeysReference, writeReference, writeSignaturesReference} from "./writers.ts";

export interface PkAndSerializedSig {
	pk: PublicKey;
	sig: Uint8Array;
}

export interface PkAndSig {
	pk: PublicKey;
	sig: Signature;
}

/**
 * Aggregate multiple public keys and multiple serialized signatures into a single blinded public key and blinded signature.
 *
 * Signatures are deserialized and validated with infinity and group checks before aggregation.
 * TODO: see if we can support unlimited sets
 */
export function aggregateWithRandomness(sets: Array<PkAndSerializedSig>): PkAndSig {
	if (sets.length > MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB) {
		throw new Error(`Number of PkAndSerializedSig exceeds the maximum of ${MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB}`);
	}

	if (sets.length === 0) {
		throw new Error("At least one PkAndSerializedSig is required");
	}

	const pksRef = writePublicKeysReference(sets.map((s) => s.pk));
	const sigsRef = writeSignaturesReference(sets.map((s) => Signature.fromBytes(s.sig, true)));
	const pkOut = new PublicKey(new Uint8Array(PUBLIC_KEY_SIZE));
	const sigOut = new Signature(new Uint8Array(SIGNATURE_LENGTH));

	const res = binding.aggregateWithRandomness(pkOut.ptr, sigOut.ptr, sets.length, pksRef, sigsRef, false, false);

	if (res) {
		throw new Error("Failed to aggregate with randomness res = " + res);
	}

	return {pk: pkOut, sig: sigOut};
}

/**
 * Aggregate multiple public keys and multiple serialized signatures into a single blinded public key and blinded signature.
 *
 * Signatures are deserialized and validated with infinity and group checks before aggregation.
 * TODO: this api only works with MacOS not Linux
 * got this error on Linux:
 * ```
 *  thread 1893 panic: reached unreachable code
 *  Panicked during a panic. Aborting.
 * ```
 */
export function asyncAggregateWithRandomness(sets: Array<PkAndSerializedSig>): Promise<PkAndSig> {
	if (sets.length > MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB) {
		throw new Error(`Number of PkAndSerializedSig exceeds the maximum of ${MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB}`);
	}

	if (sets.length === 0) {
		throw new Error("At least one PkAndSerializedSig is required");
	}

	// 1s timeout
	const TIMEOUT_MS = 1_000;
	const pkOut = new PublicKey(new Uint8Array(PUBLIC_KEY_SIZE));
	const sigOut = new Signature(new Uint8Array(SIGNATURE_LENGTH));

	return new Promise((resolve, reject) => {
		let jscallback: JSCallback | null = null;
		const timeout = setTimeout(() => {
			if (jscallback) {
				jscallback.close();
				jscallback = null;
			}
			reject(`Timeout after ${timeout}ms`);
		}, TIMEOUT_MS);

		// it's important to always close the callback
		jscallback = new JSCallback(
			(res: number): void => {
				clearTimeout(timeout);
				const _res = res;
				if (jscallback) {
					jscallback.close();
					jscallback = null;
				}
				// setTimeout to unblock zig callback thread, not sure why "res" can only be accessed once
				setTimeout(() => {
					if (_res === 0) {
						resolve({pk: pkOut, sig: sigOut});
					} else {
						reject(new Error("Failed to aggregate with randomness"));
					}
				}, 0);
			},
			{
				args: ["u32"],
				returns: "void",
				threadsafe: true,
			}
		);

		const refs = new Uint32Array(sets.length * 2);
		writePkAndSerializedSigsReference(sets, refs);

		const res = binding.aggregateWithRandomness(
			refs,
			sets.length,
			pkOut.ptr,
			sigOut.ptr,
			// it's noted in bun:ffi doc that using JSCallback.prototype.ptr is faster than JSCallback object
			jscallback.ptr
		);

		if (res !== 0) {
			clearTimeout(timeout);
			if (jscallback) {
				jscallback.close();
				jscallback = null;
			}
			reject(`Failed to aggregate with randomness res = ${res}`);
		}
	});
}

// global PkAndSerializedSig data to be reused across multiple calls
// each PkAndSerializedSig are 24 bytes
const setsData = new Uint32Array(MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB * 6);
function writePkAndSerializedSigsReference(sets: PkAndSerializedSig[], out: Uint32Array): void {
	const offset = 0;
	for (const [i, set] of sets.entries()) {
		writePkAndSerializedSigReference(set, setsData, offset + i * 6);
		// write pointer, each PkAndSerializedSig takes 8 bytes = 2 * uint32
		writeReference(setsData.subarray(i * 6, i * 6 + 6), out, i * 2);
	}
}

// each PkAndSerializedSig needs 16 bytes = 4 * uint32 for references
/**
 * Map an instance of PkAndSerializedSig in typescript to this struct in Zig:
 * ```zig
 *    const PkAndSerializedSigC = extern struct {
        pk: *pk_aff_type,
        sig: [*c]const u8,
        sig_len: usize,
    };
  * ```
 *
 */
function writePkAndSerializedSigReference(set: PkAndSerializedSig, out: Uint32Array, offset: number): void {
	writeReference(set.pk, out, offset);
	writeReference(set.sig, out, offset + 2);
	writeNumber(set.sig.length, out, offset + 4);
}
