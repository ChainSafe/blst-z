import {binding} from "./binding.js";
import {BLST_SUCCESS, SECRET_KEY_LENGTH} from "./const.js";
import {PublicKey} from "./publicKey.js";
import {Signature} from "./signature.js";
import {fromHex, toError, toHex} from "./util.js";

export class SecretKey {
	private blst_point: Uint8Array;
	private constructor(buffer: Uint8Array) {
		this.blst_point = buffer;
	}

	/**
	 * Generate a secret key deterministically from a secret byte array `ikm`.
	 *
	 * `ikm` must be at least 32 bytes long.
	 *
	 * Optionally pass `key_info` bytes to derive multiple independent keys from the same `ikm`.
	 * By default, the `key_info` is empty.
	 */
	static fromKeygen(ikm: Uint8Array, keyInfo?: Uint8Array | undefined | null): SecretKey {
		// napi automatically throws on invalid types but for Bun, need to check manually
		if (keyInfo !== undefined && !(keyInfo instanceof Uint8Array)) {
			throw new Error("Invalid key info type");
		}

		const buffer = new Uint8Array(SECRET_KEY_LENGTH);
		const res = binding.secretKeyGen(buffer, ikm, ikm.length, keyInfo ?? null, keyInfo?.length ?? 0);
		if (res !== BLST_SUCCESS) {
			throw toError(res);
		}

		return new SecretKey(buffer);
	}

	/**
	 * Generate a master secret key deterministically from a secret byte array `ikm` based on EIP-2333.
	 *
	 * `ikm` must be at least 32 bytes long.
	 *
	 * See https://eips.ethereum.org/EIPS/eip-2333
	 */
	static deriveMasterEip2333(ikm: Uint8Array): SecretKey {
		const buffer = new Uint8Array(SECRET_KEY_LENGTH);
		const res = binding.secretKeyDeriveMasterEip2333(buffer, ikm, ikm.length);
		if (res !== BLST_SUCCESS) {
			throw toError(res);
		}

		return new SecretKey(buffer);
	}

	/**
	 * Derive a child secret key from a parent secret key based on EIP-2333.
	 *
	 * See https://eips.ethereum.org/EIPS/eip-2333
	 */
	deriveChildEip2333(index: number): SecretKey {
		const buffer = new Uint8Array(SECRET_KEY_LENGTH);
		binding.secretKeyDeriveChildEip2333(buffer, this.blst_point, index);
		return new SecretKey(buffer);
	}

	/** Deserialize a secret key from a byte array. */
	static fromBytes(bytes: Uint8Array): SecretKey {
		const buffer = new Uint8Array(SECRET_KEY_LENGTH);
		const res = binding.secretKeyFromBytes(buffer, bytes, bytes.length);
		if (res !== BLST_SUCCESS) {
			throw toError(res);
		}

		return new SecretKey(buffer);
	}

	/** Deserialize a secret key from a hex string. */
	static fromHex(hex: string): SecretKey {
		const bytes = fromHex(hex);
		return SecretKey.fromBytes(bytes);
	}

	/** Serialize a secret key to a byte array. */
	toBytes(): Uint8Array {
		const bytes = new Uint8Array(SECRET_KEY_LENGTH);
		binding.secretKeyToBytes(bytes, this.blst_point);
		return bytes;
	}

	/** Serialize a secret key to a hex string. */
	toHex(): string {
		const bytes = this.toBytes();
		return toHex(bytes);
	}

	/** Return the corresponding public key */
	toPublicKey(): PublicKey {
		return PublicKey.fromSecretKey(this.blst_point);
	}

	/** Return the signature */
	sign(msg: Uint8Array): Signature {
		return Signature.sign(msg, this.blst_point);
	}
}
