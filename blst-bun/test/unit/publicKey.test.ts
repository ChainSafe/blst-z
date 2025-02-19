import { describe, it, expect, afterAll } from "bun:test";
import { closeBinding } from "../../src/binding";
import { PublicKey } from "../../src/publicKey";
import { expectEqualHex, expectNotEqualHex, sullyUint8Array } from "../utils/helpers";
import { G1_POINT_AT_INFINITY, SECRET_KEY_BYTES, invalidInputs, validPublicKey } from "../__fixtures__";
import type { CodeError } from "../utils/types";
import { SecretKey } from "../../src";
import { PUBLIC_KEY_LENGTH_COMPRESSED, PUBLIC_KEY_LENGTH_UNCOMPRESSED } from "../../src/const";

describe("PublicKey", () => {
  it("should exist", () => {
    expect(PublicKey).toBeFunction();
  });

  describe("constructors", () => {
    // no need "should have a private constructor"

    describe("deserialize", () => {
      it("should only take 48 or 96 bytes", () => {
        expect(() => PublicKey.fromBytes(Buffer.alloc(32, "*"))).toThrow("Invalid encoding");
      });

      it("should take uncompressed byte arrays", () => {
        expectEqualHex(PublicKey.fromBytes(validPublicKey.uncompressed).toBytes(), validPublicKey.compressed);
      });

      it("should take compressed byte arrays", () => {
        expectEqualHex(PublicKey.fromBytes(validPublicKey.compressed).toBytes(), validPublicKey.compressed);
      });

      describe("argument validation", () => {
        for (const [type, invalid] of invalidInputs) {
          it(`should throw on invalid pkBytes type: ${type}`, () => {
            expect(() => PublicKey.fromBytes(invalid)).toThrow();
          });
        }
        it("should throw incorrect length pkBytes", () => {
          expect(() => PublicKey.fromBytes(Buffer.alloc(12, "*"))).toThrow("Invalid encoding");
        });
      });
      it("should throw on invalid key", () => {
        try {
          PublicKey.fromBytes(sullyUint8Array(validPublicKey.compressed), true);
          throw new Error("Did not throw error for badPublicKey");
        } catch (e) {
          expect((e as CodeError).code === "BLST_POINT_NOT_ON_CURVE" || (e as CodeError).code === "BLST_BAD_ENCODING")
            .toBeTrue();
        }
      });
      it("should throw on zero key", () => {
        expect(() => PublicKey.fromBytes(Buffer.from(G1_POINT_AT_INFINITY))).toThrow("Invalid encoding");
      });
    });
    });

    describe("methods", () => {
      describe("toBytes", () => {
        const sk = SecretKey.fromBytes(SECRET_KEY_BYTES);
        const pk = sk.toPublicKey();
        it("should toBytes the key to Uint8Array", () => {
          expect(pk.toBytes()).toBeInstanceOf(Uint8Array);
        });
        it("should default to compressed serialization", () => {
          expectEqualHex(pk.toBytes(), pk.toBytes(true));
          expectNotEqualHex(pk.toBytes(), pk.toBytes(false));
        });
        it("should serialize compressed to the correct length", () => {
          expect(pk.toBytes(true)).toHaveLength(PUBLIC_KEY_LENGTH_COMPRESSED);
        });
        it("should serialize uncompressed to the correct length", () => {
          expect(pk.toBytes(false)).toHaveLength(PUBLIC_KEY_LENGTH_UNCOMPRESSED);
        });
      });
      describe("toHex", () => {
        it("should toHex string correctly", () => {
          const key = PublicKey.fromBytes(validPublicKey.compressed);
          expectEqualHex(key.toHex(true), validPublicKey.compressed);
        });
      });
      describe("keyValidate()", () => {
        it("should not throw on valid public key", () => {
          const pk = PublicKey.fromBytes(validPublicKey.uncompressed);
          expect(pk.keyValidate()).toBeUndefined();
        });
      });
    });
  });



afterAll(() => {
  // TODO: enable this on all tests cause "segmentation fault" on CI
  // closeBinding();
});