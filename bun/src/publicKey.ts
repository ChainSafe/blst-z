import {binding, writeReference} from "./binding.ts";
import {BLST_SUCCESS, PUBLIC_KEY_LENGTH_COMPRESSED, PUBLIC_KEY_LENGTH_UNCOMPRESSED} from "./const.ts";
import {fromHex, toError, toHex} from "./util.ts";

export class PublicKey {
	// this is mapped directly to `*const PublicKeyType` in Zig
	blst_point: Uint8Array;
	private constructor(buffer: Uint8Array) {
		this.blst_point = buffer;
	}

	/**
	 * Supposed to be used to mutate the public key after this call
	 */
	static defaultPublicKey(): PublicKey {
		const buffer = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
		return new PublicKey(buffer);
	}

	/**
	 * Called from SecretKey so that we keep the constructor private.
	 */
	static fromSecretKey(sk: Uint8Array): PublicKey {
		const buffer = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
		binding.secretKeyToPublicKey(buffer, sk);
		return new PublicKey(buffer);
	}

	/**
	 * Deserialize a public key from a byte array.
	 *
	 * If `pk_validate` is `true`, the public key will be infinity and group checked.
	 */
	static fromBytes(bytes: Uint8Array, pkValidate?: boolean | undefined | null): PublicKey {
		const buffer = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
		let res = binding.deserializePublicKey(buffer, bytes, bytes.length);
		if (res !== BLST_SUCCESS) {
			throw toError(res);
		}

		if (pkValidate) {
			res = binding.validatePublicKey(buffer);
			if (res !== BLST_SUCCESS) {
				throw toError(res);
			}
		}
		return new PublicKey(buffer);
	}

	/**
	 * Deserialize a public key from a hex string.
	 *
	 * If `pk_validate` is `true`, the public key will be infinity and group checked.
	 */
	static fromHex(hex: string, pkValidate?: boolean | undefined | null): PublicKey {
		const bytes = fromHex(hex);
		return PublicKey.fromBytes(bytes, pkValidate);
	}

	/** Serialize a public key to a byte array. */
	toBytes(inCompress?: boolean | undefined | null): Uint8Array {
		// this is the same to Rust binding
		const compress = inCompress ?? true;
		if (compress) {
			const out = new Uint8Array(PUBLIC_KEY_LENGTH_COMPRESSED);
			binding.compressPublicKey(out, this.blst_point);
			return out;
		}

		const out = new Uint8Array(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
		binding.serializePublicKey(out, this.blst_point);
		return out;
	}

	/** Serialize a public key to a hex string. */
	toHex(compress?: boolean | undefined | null): string {
		const bytes = this.toBytes(compress);
		return toHex(bytes);
	}

	/** Validate a public key with infinity and group check. */
	keyValidate(): void {
		const res = binding.validatePublicKey(this.blst_point);
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
const publicKeysRefs = new Uint32Array(MAX_PKS * 2);

/**
 * Map PublicKey[] in typescript to [*c]const *PublicKeyType in Zig.
 */
export function writePublicKeysReference(pks: PublicKey[]): Uint32Array {
	if (pks.length > MAX_PKS) {
		throw new Error(`Too many public keys, max is ${MAX_PKS}`);
	}

	for (let i = 0; i < pks.length; i++) {
		pks[i].writeReference(publicKeysRefs, i * 2);
	}

	return publicKeysRefs.subarray(0, pks.length * 2);
}
