import { write } from "bun";
import { binding, writeReference } from "./binding";
import { BLST_SUCCESS, MAX_SIGNATURE_SETS_PER_JOB, SIGNATURE_LENGTH_COMPRESSED, SIGNATURE_LENGTH_UNCOMPRESSED } from "./const";
import { writePublicKeysReference, type PublicKey } from "./publicKey";
import { blstErrorToReason, fromHex, toHex } from "./util";

export class Signature {
  private blst_point: Uint8Array;
  private constructor(buffer: Uint8Array) {
    this.blst_point = buffer;
  }

  /**
   * Called from SecretKey so that we keep the constructor private.
   */
  public static sign(msg: Uint8Array, sk: Uint8Array): Signature {
    const buffer = new Uint8Array(SIGNATURE_LENGTH_UNCOMPRESSED);
    binding.sign(buffer, sk, msg, msg.length);
    return new Signature(buffer);
  }

  /**
   * Deserialize a signature from a byte array.
   *
   * If `sig_validate` is `true`, the public key will be infinity and group checked.
   *
   * If `sig_infcheck` is `false`, the infinity check will be skipped.
   */
  public static fromBytes(bytes: Uint8Array, sigValidate?: boolean | undefined | null, sigInfcheck?: boolean | undefined | null): Signature {
    const buffer = new Uint8Array(SIGNATURE_LENGTH_UNCOMPRESSED);
    let res: number = 0;
    if (sigValidate) {
      res = binding.sigValidate(buffer, bytes, bytes.length, sigInfcheck ?? true);
    } else {
      res = binding.signatureFromBytes(buffer, bytes, bytes.length);
    }

    if (res !== BLST_SUCCESS) {
      throw new Error(blstErrorToReason(res));
    }

    return new Signature(buffer);
  }

  /**
   * Deserialize a signature from a hex string.
   *
   * If `sig_validate` is `true`, the public key will be infinity and group checked.
   *
   * If `sig_infcheck` is `false`, the infinity check will be skipped.
   */
  public static fromHex(hex: string, sigValidate?: boolean | undefined | null, sigInfcheck?: boolean | undefined | null): Signature {
    const bytes = fromHex(hex);
    return Signature.fromBytes(bytes, sigValidate, sigInfcheck);
  }

  /** Serialize a signature to a byte array. */
  public toBytes(inCompress?: boolean | undefined | null): Uint8Array {
    // this is the same to Rust binding
    const compress = inCompress ?? true;
    if (compress) {
      const out = new Uint8Array(SIGNATURE_LENGTH_COMPRESSED);
      binding.signatureToBytes(out, this.blst_point);
      return out;
    }

    const out = new Uint8Array(SIGNATURE_LENGTH_UNCOMPRESSED);
    binding.serializeSignature(out, this.blst_point);
    return out;
  }

  /** Serialize a signature to a hex string. */
  public toHex(compress?: boolean | undefined | null): string {
    const bytes = this.toBytes(compress);
    return toHex(bytes);
  }

  /**
   * Validate a signature with infinity and group check.
   *
   * If `sig_infcheck` is `false`, the infinity check will be skipped.
   */
  public sigValidate(sigInfcheck?: boolean | undefined | null): void {
    const res = binding.validateSignature(this.blst_point, sigInfcheck ?? true);
    if (res !== BLST_SUCCESS) {
      throw new Error(blstErrorToReason(res));
    }
  }

  /** Write reference of `blst_point` to the provided Uint32Array */
  public writeReference(out: Uint32Array, offset: number): void {
    writeReference(this.blst_point, out, offset);
  }

}

export interface SignatureSet {
  msg: Uint8Array;
  pk: PublicKey;
  sig: Signature;
};

// global pairing buffer to be reused across multiple calls
const pairing = new Uint8Array(binding.sizeOfPairing());
// global signature reference to be reused across multiple calls
const signature_reference = new Uint32Array(2);
const message_reference = new Uint32Array(2);
const public_key_reference = new Uint32Array(2);

/**
 * Verify a signature against a message and public key.
 *
 * If `pk_validate` is `true`, the public key will be infinity and group checked.
 *
 * If `sig_groupcheck` is `true`, the signature will be group checked.
 */
export function verify(msg: Uint8Array, pk: PublicKey, sig: Signature, pkValidate?: boolean | undefined | null, sigGroupcheck?: boolean | undefined | null): boolean {
  writeReference(msg, message_reference, 0);
  pk.writeReference(public_key_reference, 0);
  sig.writeReference(signature_reference, 0);

  const res = binding.verifySignature(signature_reference, sigGroupcheck ?? false, message_reference, msg.length, public_key_reference, pkValidate ?? false);
  return res === 0;
}

/**
 * Verify an aggregated signature against multiple messages and multiple public keys.
 *
 * If `pk_validate` is `true`, the public keys will be infinity and group checked.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 *
 * The down side of zig binding is all messages have to be the same length.
 */
export function aggregateVerify(msgs: Array<Uint8Array>, pks: Array<PublicKey>, sig: Signature, pkValidate?: boolean | undefined | null, sigsGroupcheck?: boolean | undefined | null): boolean {
  if (msgs.length < 1) {
    throw new Error("At least one message is required");
  }
  if (msgs.length !== pks.length) {
    throw new Error("Number of messages must be equal to the number of public keys");
  }

  const msgLen = msgs[0].length;
  for (let i = 1; i < msgs.length; i++) {
    if (msgs[i].length !== msgLen) {
      throw new Error("All messages must be the same length");
    }
  }

  sig.writeReference(signature_reference, 0);
  const msgs_ref = writeMessagesReference(msgs);
  const pks_references = writePublicKeysReference(pks);
  const res = binding.aggregateVerify(signature_reference, sigsGroupcheck ?? false, msgs_ref, msgs.length, msgLen, pks_references, pks.length, pkValidate ?? false, pairing, pairing.length);
  console.log("@@@ aggregateVerify res = ", res);
  return res == 0;
}

/**
 * Verify an aggregated signature against a single message and multiple public keys.
 *
 * Proof-of-possession is required for public keys.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 */
export function fastAggregateVerify(msg: Uint8Array, pks: Array<PublicKey>, sig: Signature, sigsGroupcheck?: boolean | undefined | null): boolean {
  sig.writeReference(signature_reference, 0);
  const pks_references = writePublicKeysReference(pks);
  const res = binding.fastAggregateVerify(signature_reference, sigsGroupcheck ?? false, msg, msg.length, pks_references, pks.length, pairing, pairing.length);
  return res === 0;
}

// global signature sets reference to be reused across multiple calls
// each 2 tems are 8 bytes, store the reference of each signature set
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


const MAX_MSGS = 128;
// global messages references to be reused across multiple calls
const messages_refs = new Uint32Array(MAX_MSGS * 2);

function writeMessagesReference(msgs: Uint8Array[]): Uint32Array {
  if (msgs.length > MAX_MSGS) {
    throw new Error(`Too many messages, max is ${MAX_MSGS}`);
  }

  for (let i = 0; i < msgs.length; i++) {
    writeReference(msgs[i], messages_refs, i * 2);
  }

  return messages_refs.subarray(0, msgs.length * 2);
}