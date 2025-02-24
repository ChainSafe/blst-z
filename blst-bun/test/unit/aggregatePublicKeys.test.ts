import { describe, it, expect } from "bun:test";
import {aggregatePublicKeys, PublicKey} from "../../src/index";
import {isEqualBytes, getTestSets, CodeError} from "../utils";
import {badPublicKey} from "../__fixtures__";

describe("Aggregate Public Keys", () => {
  const sets = getTestSets(10);
  const keys = sets.map(({pk}) => pk);

  describe("aggregatePublicKeys()", () => {
    it("should return a PublicKey", () => {
      const agg = aggregatePublicKeys(keys);
      expect(agg instanceof PublicKey).toBeTrue();
    });
    it("should be able to keyValidate PublicKey", () => {
      const agg = aggregatePublicKeys(keys);
      expect(agg.keyValidate() === undefined).toBeTrue();
    });
    it("should throw for invalid PublicKey", function () {
      try {
        aggregatePublicKeys(keys.concat(PublicKey.fromBytes(badPublicKey)), true);
        expect.fail("Did not throw error for badPublicKey");
      } catch (e) {
        const code = (e as CodeError).code ?? "";
        expect(code.includes("BLST"), `${e}`).toBeTrue();
        expect(
          code.includes("BLST_POINT_NOT_ON_CURVE") ||
            code.includes("BLST_POINT_NOT_IN_GROUP") ||
            code.includes("BLST_BAD_ENCODING")
        ).toBeTrue();
        // expect((e as Error).message.endsWith("Invalid key at index 10")).to.be.true;
      }
    });
    it("should return a key that is not in the keys array", () => {
      const agg = aggregatePublicKeys(keys);
      const serialized = agg.toBytes();
      expect(keys.find((key) => isEqualBytes(key.toBytes(), serialized)) === undefined).toBeTrue();
    });
  });
});
