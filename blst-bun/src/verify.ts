import { binding, writeReference } from "./binding";
import { PublicKey, writePublicKeysReference } from "./publicKey";
import { Signature } from "./signature";
import { pairing } from "./util";

/**
 * Verify a signature against a message and public key.
 *
 * If `pk_validate` is `true`, the public key will be infinity and group checked.
 *
 * If `sig_groupcheck` is `true`, the signature will be group checked.
 */
export function verify(msg: Uint8Array, pk: PublicKey, sig: Signature, pkValidate?: boolean | undefined | null, sigGroupcheck?: boolean | undefined | null): boolean {
  const res = binding.verifySignature(sig.blst_point, sigGroupcheck ?? false, msg, msg.length, pk.blst_point, pkValidate ?? false);
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

  const msgs_ref = writeMessagesReference(msgs);
  const pks_references = writePublicKeysReference(pks);
  const res = binding.aggregateVerify(sig.blst_point, sigsGroupcheck ?? false, msgs_ref, msgs.length, msgLen, pks_references, pks.length, pkValidate ?? false, pairing, pairing.length);
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
  const pks_references = writePublicKeysReference(pks);
  const res = binding.fastAggregateVerify(sig.blst_point, sigsGroupcheck ?? false, msg, msg.length, pks_references, pks.length, pairing, pairing.length);
  return res === 0;
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