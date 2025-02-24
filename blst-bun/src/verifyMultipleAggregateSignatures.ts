import { binding, writeReference } from "./binding";
import { MAX_SIGNATURE_SETS_PER_JOB } from "./const";
import { PublicKey } from "./publicKey";
import { Signature } from "./signature";
import { pairing } from "./util";

export interface SignatureSet {
  msg: Uint8Array;
  pk: PublicKey;
  sig: Signature;
};

// global signature sets reference to be reused across multiple calls
// each 2 items are 8 bytes, store the reference of each signature set
const signature_sets_ref = new Uint32Array(MAX_SIGNATURE_SETS_PER_JOB * 2);

/**
 * Verify multiple aggregated signatures against multiple messages and multiple public keys.
 *
 * If `pks_validate` is `true`, the public keys will be infinity and group checked.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 *
 * See https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
 */
export function verifyMultipleAggregateSignatures(sets: SignatureSet[], pksValidate?: boolean | undefined | null, sigsGroupcheck?: boolean | undefined | null): boolean {
  if (sets.length > MAX_SIGNATURE_SETS_PER_JOB) {
    throw new Error(`Number of signature sets exceeds the maximum of ${MAX_SIGNATURE_SETS_PER_JOB}`);
  }

  writeSignatureSetsReference(sets, signature_sets_ref.subarray(0, sets.length * 2));
  const msgLength = 32;
  const res = binding.verifyMultipleAggregateSignatures(signature_sets_ref, sets.length, msgLength, pksValidate ?? false, sigsGroupcheck ?? false, pairing, pairing.length);
  return res === 0;
}

// global signature set data to be reused across multiple calls
// each 6 items are 24 bytes, store 3 references of each signature set (msg + pk + sig)
const signature_sets_data = new Uint32Array(MAX_SIGNATURE_SETS_PER_JOB * 6);

function writeSignatureSetsReference(sets: SignatureSet[], out: Uint32Array): void {
  let offset = 0;
  for (const [i, set] of sets.entries()) {
    writeSignatureSetReference(set, signature_sets_data, offset + i * 6);
    // write pointer
    writeReference(signature_sets_data.subarray(i * 6, i * 6 + 6), out, i * 2);
  }
}

// each SignatureSet needs 24 bytes = 6 * uint32 for references
function writeSignatureSetReference(set: SignatureSet, out: Uint32Array, offset: number): void {
  writeReference(set.msg, out, offset);
  set.pk.writeReference(out, offset + 2);
  set.sig.writeReference(out, offset + 4);
}