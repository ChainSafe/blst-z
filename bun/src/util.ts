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

export function assertSuccess(blstErrorCode: number): void {
	if (blstErrorCode !== 0) {
		throw toError(blstErrorCode);
	}
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

import {type Pointer, read} from "bun:ffi";
