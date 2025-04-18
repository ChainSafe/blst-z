import {binding, writeUint8ArrayArray} from "./binding.js";
import {MAX_AGGREGATE_PER_JOB} from "./const.js";
import {PublicKey, writePublicKeysReference} from "./publicKey.js";
import {Signature, writeSignaturesReference} from "./signature.js";

// global public keys reference to be reused across multiple calls
// each 2 items are 8 bytes, store the reference of each public key
const publicKeysRef = new Uint32Array(MAX_AGGREGATE_PER_JOB * 2);

const signaturesRef = new Uint32Array(MAX_AGGREGATE_PER_JOB * 2);

/**
 * Aggregate multiple public keys into a single public key.
 *
 * If `pks_validate` is `true`, the public keys will be infinity and group checked.
 */
export function aggregatePublicKeys(pks: Array<PublicKey>, pksValidate?: boolean | undefined | null): PublicKey {
	if (pks.length === 0) {
		throw new Error("At least one public key is required");
	}

	const resultPks: PublicKey[] = [];

	for (let i = 0; i < pks.length; i += MAX_AGGREGATE_PER_JOB) {
		const pksBatch = pks.slice(i, Math.min(pks.length, i + MAX_AGGREGATE_PER_JOB));
		const pksRef = writePublicKeysReference(pksBatch);
		const outPk = PublicKey.defaultPublicKey();
		const res = binding.aggregatePublicKeys(outPk.blst_point, pksRef, pksBatch.length, pksValidate ?? false);

		if (res !== 0) {
			throw new Error(`Failed to aggregate public keys: ${res}`);
		}
		resultPks.push(outPk);
	}

	return resultPks.length === 1 ? resultPks[0] : aggregatePublicKeys(resultPks, pksValidate);
}

/**
 * Aggregate multiple signatures into a single signature.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 */
export function aggregateSignatures(sigs: Array<Signature>, sigsGroupcheck?: boolean | undefined | null): Signature {
	const resultSig: Signature[] = [];

	if (sigs.length === 0) {
		throw new Error("At least one signature is required");
	}

	for (let i = 0; i < sigs.length; i += MAX_AGGREGATE_PER_JOB) {
		const sigsBatch = sigs.slice(i, Math.min(sigs.length, i + MAX_AGGREGATE_PER_JOB));
		const sigsRef = writeSignaturesReference(sigsBatch);
		const outSig = Signature.defaultSignature();
		const res = binding.aggregateSignatures(outSig.blst_point, sigsRef, sigsBatch.length, sigsGroupcheck ?? false);

		if (res !== 0) {
			throw new Error(`Failed to aggregate signatures: ${res}`);
		}
		resultSig.push(outSig);
	}

	return resultSig.length === 1 ? resultSig[0] : aggregateSignatures(resultSig, sigsGroupcheck);
}

/**
 * Aggregate multiple serialized public keys into a single public key.
 *
 * If `pks_validate` is `true`, the public keys will be infinity and group checked.
 */
export function aggregateSerializedPublicKeys(
	pks: Array<Uint8Array>,
	pksValidate?: boolean | undefined | null
): PublicKey {
	if (pks.length < 1) {
		throw new Error("At least one public key is required");
	}

	const resultPublicKeys: PublicKey[] = [];

	for (let i = 0; i < pks.length; i += MAX_AGGREGATE_PER_JOB) {
		const pksBatch = pks.slice(i, Math.min(pks.length, i + MAX_AGGREGATE_PER_JOB));
		const pksRef = writeSerializedPublicKeysReference(pksBatch);
		const outPk = PublicKey.defaultPublicKey();
		const res = binding.aggregateSerializedPublicKeys(
			outPk.blst_point,
			pksRef,
			pksBatch.length,
			pks[0].length,
			pksValidate ?? false
		);

		if (res !== 0) {
			throw new Error(`Failed to aggregate serialized public keys: ${res}`);
		}
		resultPublicKeys.push(outPk);
	}

	return resultPublicKeys.length === 1 ? resultPublicKeys[0] : aggregatePublicKeys(resultPublicKeys, pksValidate);
}

/**
 * Aggregate multiple serialized signatures into a single signature.
 *
 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
 */
export function aggregateSerializedSignatures(
	sigs: Array<Uint8Array>,
	sigsGroupcheck?: boolean | undefined | null
): Signature {
	if (sigs.length < 1) {
		throw new Error("At least one signature is required");
	}

	const resultSignatures: Signature[] = [];

	for (let i = 0; i < sigs.length; i += MAX_AGGREGATE_PER_JOB) {
		const sigsBatch = sigs.slice(i, Math.min(sigs.length, i + MAX_AGGREGATE_PER_JOB));
		const sigsRef = writeSerializedSignaturesReference(sigsBatch);
		const outSig = Signature.defaultSignature();
		const res = binding.aggregateSerializedSignatures(
			outSig.blst_point,
			sigsRef,
			sigsBatch.length,
			sigs[0].length,
			sigsGroupcheck ?? false
		);

		if (res !== 0) {
			throw new Error(`Failed to aggregate serialized signatures: ${res}`);
		}
		resultSignatures.push(outSig);
	}

	return resultSignatures.length === 1 ? resultSignatures[0] : aggregateSignatures(resultSignatures, sigsGroupcheck);
}

function writeSerializedPublicKeysReference(pks: Uint8Array[]): Uint32Array {
	writeUint8ArrayArray(pks, MAX_AGGREGATE_PER_JOB, "public key", publicKeysRef);
	return publicKeysRef.subarray(0, pks.length * 2);
}

function writeSerializedSignaturesReference(sigs: Uint8Array[]): Uint32Array {
	writeUint8ArrayArray(sigs, MAX_AGGREGATE_PER_JOB, "signature", signaturesRef);
	return signaturesRef.subarray(0, sigs.length * 2);
}
