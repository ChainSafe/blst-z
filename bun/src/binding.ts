import {ptr} from "bun:ffi";
import path from "node:path";
import {openLibrary} from "@chainsafe/bun-ffi-z";

// Load the compiled Zig shared library
const fns = {
	// PublicKey functions
	validatePublicKey: {
		args: ["ptr"],
		returns: "u8",
	},
	publicKeyBytesValidate: {
		args: ["ptr", "u64"],
		returns: "u8",
	},
	publicKeyFromAggregate: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	compressPublicKey: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	serializePublicKey: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	uncompressPublicKey: {
		args: ["ptr", "ptr", "u64"],
		returns: "void",
	},
	deserializePublicKey: {
		args: ["ptr", "ptr", "u64"],
		returns: "u8",
	},
	toPublicKeyBytes: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	isPublicKeyEqual: {
		args: ["ptr", "ptr"],
		returns: "bool",
	},
	// SecretKey functions
	secretKeyGen: {
		args: ["ptr", "ptr", "u32", "ptr", "u32"],
		returns: "u8",
	},
	secretKeyDeriveMasterEip2333: {
		args: ["ptr", "ptr", "u32"],
		returns: "u8",
	},
	secretKeyDeriveChildEip2333: {
		args: ["ptr", "ptr", "u32"],
		returns: "void",
	},
	secretKeyFromBytes: {
		args: ["ptr", "ptr", "u32"],
		returns: "u8",
	},
	secretKeyToBytes: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	secretKeyToPublicKey: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	sign: {
		args: ["ptr", "ptr", "ptr", "u32"],
		returns: "void",
	},
	// Signature functions
	signatureFromBytes: {
		args: ["ptr", "ptr", "u32"],
		returns: "u8",
	},
	sigValidate: {
		args: ["ptr", "ptr", "u32", "bool"],
		returns: "u8",
	},
	signatureToBytes: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	serializeSignature: {
		args: ["ptr", "ptr"],
		returns: "void",
	},
	validateSignature: {
		args: ["ptr", "bool"],
		returns: "u8",
	},
	verifySignature: {
		args: ["ptr", "bool", "ptr", "u32", "ptr", "bool"],
		returns: "u8",
	},
	aggregateVerify: {
		args: ["ptr", "bool", "ptr", "u32", "u32", "ptr", "u32", "bool", "ptr", "u32"],
		returns: "u8",
	},
	fastAggregateVerify: {
		args: ["ptr", "bool", "ptr", "u32", "ptr", "u32", "ptr", "u32"],
		returns: "u8",
	},
	verifyMultipleAggregateSignatures: {
		args: ["ptr", "u32", "u32", "bool", "bool"],
		returns: "u32",
	},
	sizeOfPairing: {
		args: [],
		returns: "u32",
	},
	aggregatePublicKeys: {
		args: ["ptr", "ptr", "u32", "bool"],
		returns: "u32",
	},
	aggregateSignatures: {
		args: ["ptr", "ptr", "u32", "bool"],
		returns: "u32",
	},
	aggregateWithRandomness: {
		args: ["ptr", "u32", "ptr", "ptr"],
		returns: "u32",
	},
	asyncAggregateWithRandomness: {
		args: ["ptr", "u32", "ptr", "ptr", "callback"],
		returns: "u32",
	},
	aggregateSerializedPublicKeys: {
		args: ["ptr", "ptr", "u32", "u32", "bool"],
		returns: "u32",
	},
	aggregateSerializedSignatures: {
		args: ["ptr", "ptr", "u32", "u32", "bool"],
		returns: "u32",
	},
	init: {
		args: [],
		returns: "u32",
	},
	deinit: {
		args: [],
		returns: "void",
	},
};

// Load the compiled Zig shared library
// the first param is bun's cwd
//   - on dev env it's the cwd which is `./bun`
//   - on prod env it does not matter because bun-ffi-z will load platfrom-specific package like @chainsafe/blst-bun-linux-x64-gnu/libblst_min_pk.so instead
const lib = await openLibrary(path.join(import.meta.dirname, ".."), fns);
export const binding = lib.symbols;

/**
 * Initialize the Zig binding
 */
const res = binding.init();
if (res !== 0) {
	throw new Error("Failed to initialize Zig binding");
}

/**
 * Call this api to close the binding.
 */
export function closeBinding(): void {
	binding.deinit();
	lib.close();
}

/**
 * Write reference of a data to the provided Uint32Array at offset
 * TODO: may accept data + offset and compute pointer from the parent typed array. This will help to avoid `subarray()` calls.
 */
export function writeReference(data: Uint8Array | Uint32Array, out: Uint32Array, offset: number): void {
	// 2 items of uint32 means 8 of uint8
	if (offset + 2 > out.length) {
		throw new Error("Output buffer must be at least 8 bytes long");
	}

	const pointer = ptr(data);

	writeNumber(pointer, out, offset);
}

/**
 * Write a number to "usize" in Zig, which takes 8 bytes
 */
export function writeNumber(data: number, out: Uint32Array, offset: number): void {
	if (offset + 2 > out.length) {
		throw new Error("Output buffer must be at least 8 bytes long");
	}

	// TODO: check endianess, this is for little endian
	out[offset] = data & 0xffffffff;
	out[offset + 1] = Math.floor(data / Math.pow(2, 32));
}

/**
 * Common util to map Uint8Array[] to `[*c][*c]const u8` in Zig
 */
export function writeUint8ArrayArray(data: Uint8Array[], maxItem: number, tag: string, out: Uint32Array): void {
	if (data.length > maxItem) {
		throw new Error(`Too many ${tag}s, max is ${maxItem}`);
	}

	if (out.length < data.length * 2) {
		throw new Error(`Output buffer must be at least double data size. out: ${out.length}, data: ${data.length}`);
	}

	const pkLength = data[0].length;

	for (let i = 0; i < data.length; i++) {
		if (data[i].length !== pkLength) {
			throw new Error(`All ${tag}s must be the same length`);
		}
		writeReference(data[i], out, i * 2);
	}
}
