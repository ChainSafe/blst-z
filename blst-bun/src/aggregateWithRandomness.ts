import {JSCallback} from "bun:ffi";
import { binding, writeNumber, writeReference } from "./binding";
import { MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB } from "./const";
import { PublicKey } from "./publicKey";
import { Signature } from "./signature";

export interface PkAndSerializedSig {
  pk: PublicKey;
  sig: Uint8Array;
};

export interface PkAndSig {
  pk: PublicKey;
  sig: Signature;
};

// global signature sets reference to be reused across multiple calls
// each 2 tems are 8 bytes, store the reference of each PkAndSerializedSig
const pk_and_serialized_sigs_refs = new Uint32Array(MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB * 2);

const scratch_pk = new Uint8Array(binding.sizeOfScratchPk(MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB));
const scratch_sig = new Uint8Array(binding.sizeOfScratchSig(MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB));

/**
 * Aggregate multiple public keys and multiple serialized signatures into a single blinded public key and blinded signature.
 *
 * Signatures are deserialized and validated with infinity and group checks before aggregation.
 */
export function aggregateWithRandomness(sets: Array<PkAndSerializedSig>): PkAndSig {
  if (sets.length > MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB) {
    throw new Error(`Number of PkAndSerializedSig exceeds the maximum of ${MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB}`);
  }

  if (sets.length === 0) {
    throw new Error("At least one PkAndSerializedSig is required");
  }

  const refs = pk_and_serialized_sigs_refs.subarray(0, sets.length * 2);
  writePkAndSerializedSigsReference(sets, refs);
  const pkOut = PublicKey.defaultPublicKey();
  const sigOut = Signature.defaultSignature();

  const res = binding.aggregateWithRandomness(refs, sets.length, scratch_pk, scratch_pk.length, scratch_sig, scratch_sig.length, pkOut.blst_point, sigOut.blst_point);

  if (res !== 0) {
    throw new Error("Failed to aggregate with randomness res = " + res);
  }

  return { pk: pkOut, sig: sigOut};
}

/**
 * Aggregate multiple public keys and multiple serialized signatures into a single blinded public key and blinded signature.
 *
 * Signatures are deserialized and validated with infinity and group checks before aggregation.
 */
export function asyncAggregateWithRandomness(sets: Array<PkAndSerializedSig>): Promise<PkAndSig> {
  if (sets.length > MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB) {
    throw new Error(`Number of PkAndSerializedSig exceeds the maximum of ${MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB}`);
  }

  if (sets.length === 0) {
    throw new Error("At least one PkAndSerializedSig is required");
  }

  return new Promise((resolve, reject) => {
    const pkOut = PublicKey.defaultPublicKey();
    const sigOut = Signature.defaultSignature();

    const jscallback = new JSCallback((res: number): void => {
      if (res === 0) {
        // setTimeout to unblock zig callback thread, not sure why "res" can only be accessed once
        setTimeout(() => {
          resolve({ pk: pkOut, sig: sigOut });
        }, 0);
      } else {
        setTimeout(() => {
          // setTimeout to unblock zig callback thread, not sure why "res" can only be accessed once
          reject(new Error("Failed to aggregate with randomness"));
        }, 0);
      }
    }, {
      "args": ["u32"],
      "returns": "void",
    });

    const refs = pk_and_serialized_sigs_refs.subarray(0, sets.length * 2);
    writePkAndSerializedSigsReference(sets, refs);

    const res = binding.asyncAggregateWithRandomness(pk_and_serialized_sigs_refs, sets.length, scratch_pk, scratch_pk.length, scratch_sig, scratch_sig.length, pkOut.blst_point, sigOut.blst_point, jscallback);

    if (res !== 0) {
      throw new Error("Failed to aggregate with randomness res = " + res);
    }
  });
}


// global PkAndSerializedSig data to be reused across multiple calls
// each PkAndSerializedSig are 24 bytes
const sets_data = new Uint32Array(MAX_AGGREGATE_WITH_RANDOMNESS_PER_JOB * 6);
function writePkAndSerializedSigsReference(sets: PkAndSerializedSig[], out: Uint32Array): void {
  let offset = 0;
  for (const [i, set] of sets.entries()) {
    writePkAndSerializedSigReference(set, sets_data, offset + i * 6);
    // write pointer, each PkAndSerializedSig takes 8 bytes = 2 * uint32
    writeReference(sets_data.subarray(i * 6, i * 6 + 6), out, i * 2);
  }
};

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