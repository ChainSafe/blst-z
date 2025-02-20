import { binding, writeReference } from "./binding";
import { BLST_SUCCESS, SIGNATURE_LENGTH_COMPRESSED, SIGNATURE_LENGTH_UNCOMPRESSED } from "./const";
import { blstErrorToReason, fromHex, toHex } from "./util";

export class Signature {
  // this is mapped directly to `*const SignatureType` in Zig
  blst_point: Uint8Array;
  private constructor(buffer: Uint8Array) {
    this.blst_point = buffer;
  }

  /**
   * Called from SecretKey so that we keep the constructor private.
   */
  public static sign(msg: Uint8Array, sk: Uint8Array): Signature {
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
  public static fromBytes(bytes: Uint8Array, sigValidate?: boolean | undefined | null, sigInfcheck?: boolean | undefined | null): Signature {
    const buffer = new Uint8Array(SIGNATURE_LENGTH_UNCOMPRESSED);
    let res: number = 0;
    if (sigValidate) {
      res = binding.sigValidate(buffer, bytes, bytes.length, sigInfcheck ?? true);
    } else {
      res = binding.signatureFromBytes(buffer, bytes, bytes.length);
    }

    if (res !== BLST_SUCCESS) {
      throw new Error(blstErrorToReason(res));
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
  public static fromHex(hex: string, sigValidate?: boolean | undefined | null, sigInfcheck?: boolean | undefined | null): Signature {
    const bytes = fromHex(hex);
    return Signature.fromBytes(bytes, sigValidate, sigInfcheck);
  }

  /** Serialize a signature to a byte array. */
  public toBytes(inCompress?: boolean | undefined | null): Uint8Array {
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
  public toHex(compress?: boolean | undefined | null): string {
    const bytes = this.toBytes(compress);
    return toHex(bytes);
  }

  /**
   * Validate a signature with infinity and group check.
   *
   * If `sig_infcheck` is `false`, the infinity check will be skipped.
   */
  public sigValidate(sigInfcheck?: boolean | undefined | null): void {
    const res = binding.validateSignature(this.blst_point, sigInfcheck ?? true);
    if (res !== BLST_SUCCESS) {
      throw new Error(blstErrorToReason(res));
    }
  }

  /** Write reference of `blst_point` to the provided Uint32Array */
  public writeReference(out: Uint32Array, offset: number): void {
    writeReference(this.blst_point, out, offset);
  }

}
