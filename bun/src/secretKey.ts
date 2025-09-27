import type {Pointer} from "bun:ffi";
import {binding} from "./binding.js";
import {PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_LENGTH} from "./const.js";
import {PublicKey} from "./publicKey.js";
import {Signature} from "./signature.js";
import {assertSuccess, fromHex, toHex} from "./util.js";

export class SecretKey {
	private ptr: Uint8Array | Pointer;

	private constructor(ptr: Uint8Array | Pointer) {
		this.ptr = ptr;
	}

	/**
	 * Generate a secret key deterministically from a secret byte array `ikm`.
	 *
	 * `ikm` must be at least 32 bytes long.
	 */
	static fromKeygen(ikm: Uint8Array): SecretKey {
		const buffer = new Uint8Array(SECRET_KEY_SIZE);
		assertSuccess(binding.secretKeyKeyGen(buffer, ikm, ikm.length));

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
		const buffer = new Uint8Array(SECRET_KEY_SIZE);
		assertSuccess(binding.secretKeyDeriveMasterEip2333(buffer, ikm, ikm.length));

		return new SecretKey(buffer);
	}

	/**
	 * Derive a child secret key from a parent secret key based on EIP-2333.
	 *
	 * See https://eips.ethereum.org/EIPS/eip-2333
	 */
	deriveChildEip2333(index: number): SecretKey {
		const buffer = new Uint8Array(SECRET_KEY_SIZE);
		binding.secretKeyDeriveChildEip2333(buffer, this.ptr, index);
		return new SecretKey(buffer);
	}

	/** Deserialize a secret key from a byte array. */
	static fromBytes(bytes: Uint8Array): SecretKey {
		const buffer = new Uint8Array(SECRET_KEY_SIZE);
		assertSuccess(binding.secretKeyFromBytes(buffer, bytes, bytes.length));

		return new SecretKey(buffer);
	}

	/** Deserialize a secret key from a hex string. */
	static fromHex(hex: string): SecretKey {
		const bytes = fromHex(hex);
		return SecretKey.fromBytes(bytes);
	}

	/** Serialize a secret key to a byte array. */
	toBytes(): Uint8Array {
		const bytes = new Uint8Array(SECRET_KEY_SIZE);
		binding.secretKeyToBytes(bytes, this.ptr);
		return bytes;
	}

	/** Serialize a secret key to a hex string. */
	toHex(): string {
		const bytes = this.toBytes();
		return toHex(bytes);
	}

	/** Return the corresponding public key */
	toPublicKey(): PublicKey {
		const pk = new Uint8Array(PUBLIC_KEY_SIZE);
		binding.secretKeyToPublicKey(pk, this.ptr);
		return new PublicKey(pk);
	}

	/** Return the signature */
	sign(msg: Uint8Array): Signature {
		if (msg.length === 0) {
			throw new Error("Message cannot be empty");
		}

		const sig = new Uint8Array(SIGNATURE_LENGTH);
		binding.secretKeySign(sig, this.ptr, msg, msg.length);
		return new Signature(sig);
	}
}
