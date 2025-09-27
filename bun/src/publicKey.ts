import type {Pointer} from "bun:ffi";
import {binding} from "./binding.ts";
import {PUBLIC_KEY_COMPRESS_SIZE, PUBLIC_KEY_SIZE} from "./const.ts";
import {assertSuccess, fromHex, toHex} from "./util.ts";

export class PublicKey {
	// this is mapped directly to `*const PublicKey` in Zig
	ptr: Uint8Array | Pointer;

	constructor(ptr: Uint8Array | Pointer) {
		this.ptr = ptr;
	}

	/**
	 * Deserialize a public key from a byte array.
	 *
	 * If `pk_validate` is `true`, the public key will be infinity and group checked.
	 */
	static fromBytes(bytes: Uint8Array, pkValidate?: boolean | undefined | null): PublicKey {
		if (bytes.length !== PUBLIC_KEY_COMPRESS_SIZE) {
			throw new Error("Invalid encoding");
		}

		const buffer = new Uint8Array(PUBLIC_KEY_SIZE);
		assertSuccess(binding.publicKeyFromBytes(buffer, bytes, bytes.length));

		if (pkValidate) {
			assertSuccess(binding.publicKeyValidate(buffer));
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
	toBytes(): Uint8Array {
		const out = new Uint8Array(PUBLIC_KEY_COMPRESS_SIZE);
		binding.publicKeyToBytes(out, this.ptr);
		return out;
	}

	/** Serialize a public key to a hex string. */
	toHex(): string {
		const bytes = this.toBytes();
		return toHex(bytes);
	}

	/** Validate a public key with infinity and group check. */
	keyValidate(): void {
		assertSuccess(binding.publicKeyValidate(this.ptr));
	}
}
