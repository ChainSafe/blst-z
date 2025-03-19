import {binding, writeReference} from "./binding.js";
import {BLST_SUCCESS, SIGNATURE_LENGTH_COMPRESSED, SIGNATURE_LENGTH_UNCOMPRESSED} from "./const.js";
import {fromHex, toError, toHex} from "./util.js";

export class Signature {
	// this is mapped directly to `*const SignatureType` in Zig
	blst_point: Uint8Array;
	private constructor(buffer: Uint8Array) {
		this.blst_point = buffer;
	}

	/**
	 * Supposed to be used to mutate the signature after this call
	 */
	static defaultSignature(): Signature {
		const buffer = new Uint8Array(SIGNATURE_LENGTH_UNCOMPRESSED);
		return new Signature(buffer);
	}

	/**
	 * Called from SecretKey so that we keep the constructor private.
	 */
	static sign(msg: Uint8Array, sk: Uint8Array): Signature {
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
	static fromBytes(
		bytes: Uint8Array,
		sigValidate?: boolean | undefined | null,
		sigInfcheck?: boolean | undefined | null
	): Signature {
		const buffer = new Uint8Array(SIGNATURE_LENGTH_UNCOMPRESSED);
		let res = 0;
		if (sigValidate) {
			res = binding.sigValidate(buffer, bytes, bytes.length, sigInfcheck ?? true);
		} else {
			res = binding.signatureFromBytes(buffer, bytes, bytes.length);
		}

		if (res !== BLST_SUCCESS) {
			throw toError(res);
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
	static fromHex(
		hex: string,
		sigValidate?: boolean | undefined | null,
		sigInfcheck?: boolean | undefined | null
	): Signature {
		const bytes = fromHex(hex);
		return Signature.fromBytes(bytes, sigValidate, sigInfcheck);
	}

	/** Serialize a signature to a byte array. */
	toBytes(inCompress?: boolean | undefined | null): Uint8Array {
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
	toHex(compress?: boolean | undefined | null): string {
		const bytes = this.toBytes(compress);
		return toHex(bytes);
	}

	/**
	 * Validate a signature with infinity and group check.
	 *
	 * If `sig_infcheck` is `false`, the infinity check will be skipped.
	 */
	sigValidate(sigInfcheck?: boolean | undefined | null): void {
		const res = binding.validateSignature(this.blst_point, sigInfcheck ?? true);
		if (res !== BLST_SUCCESS) {
			throw toError(res);
		}
	}

	/** Write reference of `blst_point` to the provided Uint32Array */
	writeReference(out: Uint32Array, offset: number): void {
		writeReference(this.blst_point, out, offset);
	}
}

const MAX_PKS = 128;
// global public key references to be reused across multiple calls
const signaturesRefs = new Uint32Array(MAX_PKS * 2);

/**
 * Map Signature[] in typescript to [*c]const *SignatureType in Zig.
 */
export function writeSignaturesReference(sigs: Signature[]): Uint32Array {
	if (sigs.length > MAX_PKS) {
		throw new Error(`Too many signatures, max is ${MAX_PKS}`);
	}

	for (let i = 0; i < sigs.length; i++) {
		sigs[i].writeReference(signaturesRefs, i * 2);
	}

	return signaturesRefs.subarray(0, sigs.length * 2);
}
