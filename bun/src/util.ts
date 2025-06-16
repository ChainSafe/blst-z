import {ptr} from "bun:ffi";
import {binding, close} from "./binding.js";

// global pairing buffer to be reused across multiple calls
export const pairing = new Uint8Array(binding.sizeOfPairing());

export function toHex(buffer: Uint8Array | Parameters<typeof Buffer.from>[0]): string {
	if (Buffer.isBuffer(buffer)) {
		return "0x" + buffer.toString("hex");
	}

	if (buffer instanceof Uint8Array) {
		return "0x" + Buffer.from(buffer.buffer, buffer.byteOffset, buffer.length).toString("hex");
	}

	return "0x" + Buffer.from(buffer).toString("hex");
}

export function fromHex(hex: string): Uint8Array {
	const b = Buffer.from(hex.replace("0x", ""), "hex");
	return new Uint8Array(b.buffer, b.byteOffset, b.length);
}

export function toError(blstErrorCode: number): Error {
	const message = blstErrorToReason(blstErrorCode);
	const error = new Error(message);
	// this make it compliant to napi-rs binding
	(error as unknown as {code: string}).code = blstErrorToCode(blstErrorCode);
	return error;
}

function blstErrorToReason(blstErrorCode: number): string {
	switch (blstErrorCode) {
		case 0:
			return "BLST_SUCCESS";
		case 1:
			return "Invalid encoding";
		case 2:
			return "Point not on curve";
		case 3:
			return "Point not in group";
		case 4:
			return "Aggregation type mismatch";
		case 5:
			return "Verification failed";
		case 6:
			return "Public key is infinity";
		case 7:
			return "Invalid scalar";
		default:
			return `Unknown error code ${blstErrorCode}`;
	}
}

export function blstErrorToCode(blstError: number): string {
	switch (blstError) {
		case 0:
			return "BLST_SUCCESS";
		case 1:
			return "BLST_BAD_ENCODING";
		case 2:
			return "BLST_POINT_NOT_ON_CURVE";
		case 3:
			return "BLST_POINT_NOT_IN_GROUP";
		case 4:
			return "BLST_AGGR_TYPE_MISMATCH";
		case 5:
			return "BLST_VERIFY_FAIL";
		case 6:
			return "BLST_PK_IS_INFINITY";
		case 7:
			return "BLST_BAD_SCALAR";
		default:
			return `Unknown error code ${blstError}`;
	}
}

let initialized = false;

/**
 * Initialize the Zig binding
 */
export function initBinding(): void {
	if (initialized) {
		return;
	}
	initialized = true;

	const res = binding.init();
	if (res !== 0) {
		throw new Error("Failed to initialize Zig binding");
	}
}

/**
 * Call this api to close the binding.
 */
export function closeBinding(): void {
	if (!initialized) {
		return;
	}
	initialized = false;
	binding.deinit();
	close();
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
