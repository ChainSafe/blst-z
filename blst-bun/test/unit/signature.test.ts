import { describe, it, expect, afterAll } from "bun:test";
import { closeBinding } from "../../src/binding";
import { expectEqualHex, expectNotEqualHex, sullyUint8Array } from "../utils/helpers";
import {KEY_MATERIAL, invalidInputs, validSignature } from "../__fixtures__";
import { SecretKey, Signature } from "../../src";
import { SIGNATURE_LENGTH_COMPRESSED, SIGNATURE_LENGTH_UNCOMPRESSED } from "../../src/const";

describe("Signature", () => {
  it("should exist", () => {
    expect(Signature).toBeFunction();
  });
  describe("constructor", () => {
    // skip "should have a private new Signature()"
    describe("Signature.fromBytes()", () => {
      it("should take uncompressed byte arrays", () => {
        expectEqualHex(Signature.fromBytes(validSignature.uncompressed).toBytes(), validSignature.compressed);
      });
      it("should take compressed byte arrays", () => {
        expectEqualHex(Signature.fromBytes(validSignature.compressed).toBytes(), validSignature.compressed);
      });
      describe("argument validation", () => {
        for (const [type, invalid] of invalidInputs) {
          it(`should throw on invalid pkBytes type: ${type}`, () => {
            expect(() => Signature.fromBytes(invalid)).toThrow();
          });
        }
        it("should only take 96 or 192 bytes", () => {
          expect(() => Signature.fromBytes(Buffer.alloc(32, "*"))).toThrow("Invalid encoding");
        });
      });
      it("should throw on invalid key", () => {
        expect(() => Signature.fromBytes(sullyUint8Array(validSignature.compressed))).toThrow("Invalid encoding");
      });
    });
  });

  describe("methods", () => {
    describe("toBytes", () => {
      const sig = SecretKey.fromKeygen(KEY_MATERIAL).sign(Buffer.from("some fancy message"));
      it("should toBytes the signature to Uint8Array", () => {
        expect(sig.toBytes()).toBeInstanceOf(Uint8Array);
      });
      it("should default to compressed serialization", () => {
        expectEqualHex(sig.toBytes(), sig.toBytes(true));
        expectNotEqualHex(sig.toBytes(), sig.toBytes(false));
      });
      it("should serialize compressed to the correct length", () => {
        expect(sig.toBytes(true)).toHaveLength(SIGNATURE_LENGTH_COMPRESSED);
      });
      it("should serialize uncompressed to the correct length", () => {
        expect(sig.toBytes(false)).toHaveLength(SIGNATURE_LENGTH_UNCOMPRESSED);
      });
    });
    describe("toHex", () => {
      it("should toHex string correctly", () => {
        const key = Signature.fromBytes(validSignature.compressed);
        expectEqualHex(key.toHex(true), validSignature.compressed);
      });
    });
    describe("sigValidate()", () => {
      it("should return undefined for valid", () => {
        const sig = Signature.fromBytes(validSignature.compressed);
        expect(sig.sigValidate()).toBeUndefined();
      });
      it("should throw for invalid", () => {
        const pkSeed = Signature.fromBytes(validSignature.compressed);
        const sig = Signature.fromBytes(Uint8Array.from([...pkSeed.toBytes().subarray(0, 94), ...Buffer.from("a1")]));
        expect(() => sig.sigValidate()).toThrow("Point not in group");
      });
    });
  });
});

afterAll(() => {
  // TODO: enable this on all tests cause "segmentation fault" on CI
  // closeBinding();
});