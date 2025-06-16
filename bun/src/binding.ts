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
export const close = lib.close;