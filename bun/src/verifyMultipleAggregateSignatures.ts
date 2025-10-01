import {binding} from "./binding.js";
import {msgsU8, writeMessages} from "./buffer.ts";
import {MAX_SIGNATURE_SETS_PER_JOB} from "./const.js";
import type {PublicKey} from "./publicKey.js";
import type {Signature} from "./signature.js";
import {pairing} from "./util.js";
import {writePublicKeysReference, writeReference, writeSignaturesReference} from "./writers.ts";

export interface SignatureSet {
	msg: Uint8Array;
	pk: PublicKey;
	sig: Signature;
}

/**
 * Verify multiple aggregated signatures against multiple messages and multiple public keys.
 *
 * If `pks_validate` is `true`, the public keys will be infinity and group checked.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 *
 * See https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
 */
export function verifyMultipleAggregateSignatures(
	sets: SignatureSet[],
	pksValidate?: boolean | undefined | null,
	sigsGroupcheck?: boolean | undefined | null
): boolean {
	if (sets.length > MAX_SIGNATURE_SETS_PER_JOB) {
		throw new Error(`Number of signature sets exceeds the maximum of ${MAX_SIGNATURE_SETS_PER_JOB}`);
	}

	const msgLength = 32;
	for (const set of sets) {
		if (set.msg.length !== msgLength) {
			throw new Error("All messages must be 32 bytes");
		}
	}
	const pksRef = writePublicKeysReference(sets.map((s) => s.pk));
	const sigsRef = writeSignaturesReference(sets.map((s) => s.sig));
	writeMessages(sets.map((s) => s.msg));

	const res = binding.signatureVerifyMultipleAggregateSignatures(
		sets.length,
		msgsU8,
		pksRef,
		pksValidate ?? false,
		sigsRef,
		sigsGroupcheck ?? false
	);
	return res === 0;
}
