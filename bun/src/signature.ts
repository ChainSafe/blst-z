import type {Pointer} from "bun:ffi";
import {binding} from "./binding.js";
import {msgsU8, pksU8, writeMessages, writePublicKeys} from "./buffer.js";
import {SIGNATURE_LENGTH, SIGNATURE_LENGTH_COMPRESSED} from "./const.js";
import type {PublicKey} from "./publicKey.js";
import {assertSuccess, fromHex, toHex} from "./util.js";

export class Signature {
	// this is mapped directly to `*const Signature` in Zig
	ptr: Uint8Array | Pointer;

	constructor(ptr: Uint8Array | Pointer) {
		this.ptr = ptr;
	}

	/**
	 * Deserialize a signature from a byte array.
	 *
	 * If `sig_validate` is `true`, the public key will be infinity and group checked.
	 *
	 * If `sig_infcheck` is `false`, the infinity check will be skipped.
	 */
	static fromBytes(
		bytes: Uint8Array,
		sigValidate?: boolean | undefined | null,
		sigInfcheck?: boolean | undefined | null
	): Signature {
		const buffer = new Uint8Array(SIGNATURE_LENGTH);
		const sig = new Signature(buffer);

		assertSuccess(binding.signatureFromBytes(sig.ptr, bytes, bytes.length));

		if (sigValidate) {
			assertSuccess(binding.signatureValidate(sig.ptr, sigInfcheck ?? true));
		}

		return sig;
	}

	/**
	 * Deserialize a signature from a hex string.
	 *
	 * If `sig_validate` is `true`, the public key will be infinity and group checked.
	 *
	 * If `sig_infcheck` is `false`, the infinity check will be skipped.
	 */
	static fromHex(
		hex: string,
		sigValidate?: boolean | undefined | null,
		sigInfcheck?: boolean | undefined | null
	): Signature {
		const bytes = fromHex(hex);
		return Signature.fromBytes(bytes, sigValidate, sigInfcheck);
	}

	/** Serialize a signature to a byte array. */
	toBytes(): Uint8Array {
		const out = new Uint8Array(SIGNATURE_LENGTH_COMPRESSED);
		binding.signatureToBytes(out, this.ptr);
		return out;
	}

	/** Serialize a signature to a hex string. */
	toHex(): string {
		const bytes = this.toBytes();
		return toHex(bytes);
	}

	/**
	 * Validate a signature with infinity and group check.
	 *
	 * If `sig_infcheck` is `false`, the infinity check will be skipped.
	 */
	sigValidate(sigInfcheck?: boolean | undefined | null): void {
		assertSuccess(binding.signatureValidate(this.ptr, sigInfcheck ?? true));
	}

	/**
	 * Verify a signature against a message and public key.
	 *
	 * If `pk_validate` is `true`, the public key will be infinity and group checked.
	 *
	 * If `sig_groupcheck` is `true`, the signature will be group checked.
	 */
	verify(
		msg: Uint8Array,
		pk: PublicKey,
		pkValidate?: boolean | undefined | null,
		sigGroupcheck?: boolean | undefined | null
	): boolean {
		if (msg.length === 0) {
			throw new Error("Message cannot be empty");
		}

		const res = binding.signatureVerify(this.ptr, sigGroupcheck ?? false, msg, msg.length, pk.ptr, pkValidate ?? false);
		return res === 0;
	}

	/**
	 * Verify an aggregated signature against a single message and multiple public keys.
	 *
	 * Proof-of-possession is required for public keys.
	 *
	 * If `sigs_groupcheck` is `true`, the signatures will be group checked.
	 */
	fastAggregateVerify(msg: Uint8Array, pks: PublicKey[], sigsGroupcheck?: boolean | undefined | null): boolean {
		if (msg.length !== 32) {
			throw new Error("Message must be 32 bytes long");
		}

		writePublicKeys(pks);
		const res = binding.signatureFastAggregateVerify(this.ptr, sigsGroupcheck ?? false, msg, pksU8, pks.length);
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
	aggregateVerify(
		msgs: Array<Uint8Array>,
		pks: Array<PublicKey>,
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

		for (let i = 0; i < msgs.length; i++) {
			if (msgs[i].length !== 32) {
				throw new Error("All messages must be 32 bytes long");
			}
		}

		writeMessages(msgs);
		writePublicKeys(pks);
		const res = binding.signatureAggregateVerify(
			this.ptr,
			sigsGroupcheck ?? false,
			msgsU8,
			pksU8,
			pks.length,
			pkValidate ?? false
		);
		return res === 0;
	}
}
