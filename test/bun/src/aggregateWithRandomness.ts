import {JSCallback} from "bun:ffi";
import {binding, writeNumber, writeReference} from "./binding.js";
import {MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB} from "./const.js";
import {PublicKey} from "./publicKey.js";
import {Signature} from "./signature.js";

export interface PkAndSerializedSig {
	pk: PublicKey;
	sig: Uint8Array;
}

export interface PkAndSig {
	pk: PublicKey;
	sig: Signature;
}

// global signature sets reference to be reused across multiple calls
// each 2 tems are 8 bytes, store the reference of each PkAndSerializedSig
const pkAndSerializedSigsRefs = new Uint32Array(MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB * 2);

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

	const refs = pkAndSerializedSigsRefs.subarray(0, sets.length * 2);
	writePkAndSerializedSigsReference(sets, refs);
	const pkOut = PublicKey.defaultPublicKey();
	const sigOut = Signature.defaultSignature();

	const res = binding.aggregateWithRandomness(refs, sets.length, pkOut.blst_point, sigOut.blst_point);

	if (res !== 0) {
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
	const pkOut = PublicKey.defaultPublicKey();
	const sigOut = Signature.defaultSignature();

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

		// cannot reuse pkAndSerializedSigsRefs() due to async nature
		const refs = new Uint32Array(sets.length * 2);
		writePkAndSerializedSigsReference(sets, refs);

		const res = binding.asyncAggregateWithRandomness(
			refs,
			sets.length,
			pkOut.blst_point,
			sigOut.blst_point,
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
	set.pk.writeReference(out, offset);
	writeReference(set.sig, out, offset + 2);
	writeNumber(set.sig.length, out, offset + 4);
}
