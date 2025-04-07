import {binding, writeReference} from "./binding.js";
import {type PublicKey, writePublicKeysReference} from "./publicKey.js";
import type {Signature} from "./signature.js";
import {pairing} from "./util.js";

/**
 * Verify a signature against a message and public key.
 *
 * If `pk_validate` is `true`, the public key will be infinity and group checked.
 *
 * If `sig_groupcheck` is `true`, the signature will be group checked.
 */
export function verify(
	msg: Uint8Array,
	pk: PublicKey,
	sig: Signature,
	pkValidate?: boolean | undefined | null,
	sigGroupcheck?: boolean | undefined | null
): boolean {
	const res = binding.verifySignature(
		sig.blst_point,
		sigGroupcheck ?? false,
		msg,
		msg.length,
		pk.blst_point,
		pkValidate ?? false
	);
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
export function aggregateVerify(
	msgs: Array<Uint8Array>,
	pks: Array<PublicKey>,
	sig: Signature,
	pkValidate?: boolean | undefined | null,
	sigsGroupcheck?: boolean | undefined | null
): boolean {
	if (msgs.length < 1) {
		// this is the same to the original napi-rs blst-ts
		return false;
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

	const msgsRef = writeMessagesReference(msgs);
	const pksReferences = writePublicKeysReference(pks);
	const res = binding.aggregateVerify(
		sig.blst_point,
		sigsGroupcheck ?? false,
		msgsRef,
		msgs.length,
		msgLen,
		pksReferences,
		pks.length,
		pkValidate ?? false,
		pairing,
		pairing.length
	);
	return res === 0;
}

/**
 * Verify an aggregated signature against a single message and multiple public keys.
 *
 * Proof-of-possession is required for public keys.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 */
export function fastAggregateVerify(
	msg: Uint8Array,
	pks: Array<PublicKey>,
	sig: Signature,
	sigsGroupcheck?: boolean | undefined | null
): boolean {
	const pksReferences = writePublicKeysReference(pks);
	const res = binding.fastAggregateVerify(
		sig.blst_point,
		sigsGroupcheck ?? false,
		msg,
		msg.length,
		pksReferences,
		pks.length,
		pairing,
		pairing.length
	);
	return res === 0;
}

const MAX_MSGS = 128;
// global messages references to be reused across multiple calls
const messagesRefs = new Uint32Array(MAX_MSGS * 2);

function writeMessagesReference(msgs: Uint8Array[]): Uint32Array {
	if (msgs.length > MAX_MSGS) {
		throw new Error(`Too many messages, max is ${MAX_MSGS}`);
	}

	for (let i = 0; i < msgs.length; i++) {
		writeReference(msgs[i], messagesRefs, i * 2);
	}

	return messagesRefs.subarray(0, msgs.length * 2);
}
