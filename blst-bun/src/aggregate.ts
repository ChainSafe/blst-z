import { binding, writeUint8ArrayArray } from "./binding";
import { MAX_AGGREGATE_PER_JOB } from "./const";
import {PublicKey, writePublicKeysReference} from "./publicKey";
import { Signature, writeSignaturesReference } from "./signature";


// global public keys reference to be reused across multiple calls
// each 2 items are 8 bytes, store the reference of each public key
const public_keys_ref = new Uint32Array(MAX_AGGREGATE_PER_JOB * 2);

const signatures_ref = new Uint32Array(MAX_AGGREGATE_PER_JOB * 2);

/**
 * Aggregate multiple public keys into a single public key.
 *
 * If `pks_validate` is `true`, the public keys will be infinity and group checked.
 */
export function aggregatePublicKeys(pks: Array<PublicKey>, pksValidate?: boolean | undefined | null): PublicKey {
  if (pks.length > MAX_AGGREGATE_PER_JOB) {
    throw new Error("Too many public keys");
  }

  const pks_ref = writePublicKeysReference(pks);

  const defaultPk = PublicKey.defaultPublicKey();
  const res = binding.aggregatePublicKeys(defaultPk.blst_point, pks_ref, pks.length, pksValidate ?? false);
  if (res !== 0) {
    throw new Error(`Failed to aggregate public keys: ${res}`);
  }

  return defaultPk;
}

/**
 * Aggregate multiple signatures into a single signature.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 */
export function aggregateSignatures(sigs: Array<Signature>, sigsGroupcheck?: boolean | undefined | null): Signature {
  if (sigs.length > MAX_AGGREGATE_PER_JOB) {
    throw new Error("Too many signatures");
  }

  const sigs_ref = writeSignaturesReference(sigs);

  const defaultSig = Signature.defaultSignature();
  const res = binding.aggregateSignatures(defaultSig.blst_point, sigs_ref, sigs.length, sigsGroupcheck ?? false);
  if (res !== 0) {
    throw new Error(`Failed to aggregate signatures: ${res}`);
  }

  return defaultSig;
}

const pks_ref = new Uint32Array(2);

/**
 * Aggregate multiple serialized public keys into a single public key.
 *
 * If `pks_validate` is `true`, the public keys will be infinity and group checked.
 */
export function aggregateSerializedPublicKeys(pks: Array<Uint8Array>, pksValidate?: boolean | undefined | null): PublicKey {
  if (pks.length > MAX_AGGREGATE_PER_JOB) {
    throw new Error("Too many public keys");
  }

  if (pks.length < 1) {
    throw new Error("At least one public key is required");
  }

  const pks_ref = writeSerializedPublicKeysReference(pks);

  const defaultPk = PublicKey.defaultPublicKey();
  const res = binding.aggregateSerializedPublicKeys(defaultPk.blst_point, pks_ref, pks.length, pks[0].length, pksValidate ?? false);
  if (res !== 0) {
    throw new Error(`Failed to aggregate serialized public keys: ${res}`);
  }

  return defaultPk;
}

/**
 * Aggregate multiple serialized signatures into a single signature.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 */
export function aggregateSerializedSignatures(sigs: Array<Uint8Array>, sigsGroupcheck?: boolean | undefined | null): Signature {
  if (sigs.length > MAX_AGGREGATE_PER_JOB) {
    throw new Error("Too many signatures");
  }

  if (sigs.length < 1) {
    throw new Error("At least one signature is required");
  }

  const sigs_ref = writeSerializedSignaturesReference(sigs);

  const defaultSig = Signature.defaultSignature();
  const res = binding.aggregateSerializedSignatures(defaultSig.blst_point, sigs_ref, sigs.length, sigs[0].length, sigsGroupcheck ?? false);
  if (res !== 0) {
    throw new Error(`Failed to aggregate serialized signatures: ${res}`);
  }

  return defaultSig;
}


function writeSerializedPublicKeysReference(pks: Uint8Array[]): Uint32Array {
  writeUint8ArrayArray(pks, MAX_AGGREGATE_PER_JOB, "public key", public_keys_ref);
  return public_keys_ref.subarray(0, pks.length * 2);
}

function writeSerializedSignaturesReference(sigs: Uint8Array[]): Uint32Array {
  writeUint8ArrayArray(sigs, MAX_AGGREGATE_PER_JOB, "signature", signatures_ref);
  return signatures_ref.subarray(0, sigs.length * 2);
}