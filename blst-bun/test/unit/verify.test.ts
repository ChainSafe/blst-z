import { describe, it, expect, afterAll, beforeAll } from "bun:test";

import {aggregateVerify, fastAggregateVerify, verify} from "../../src/verify";
import {sullyUint8Array, getTestSet} from "../utils";
import {type TestSet} from "../utils/types";

describe("Verify", () => {
  let testSet: TestSet;
  beforeAll(() => {
    testSet = getTestSet();
  });

  describe("verify", () => {
    it("should return a boolean", () => {
      expect(verify(testSet.msg, testSet.pk, testSet.sig)).toBeBoolean();
    });
    describe("should default to false", () => {
      it("should handle invalid message", () => {
        expect(verify(sullyUint8Array(testSet.msg), testSet.pk, testSet.sig)).toBeFalse();
      });
    });
    it("should return true for valid sets", () => {
      expect(verify(testSet.msg, testSet.pk, testSet.sig)).toBeTrue();
    });
  });
});

describe("Aggregate Verify", () => {
  let testSet: TestSet;
  beforeAll(() => {
    testSet = getTestSet();
  });
  describe("aggregateVerify", () => {
    it("should return a boolean", () => {
      expect(aggregateVerify([testSet.msg], [testSet.pk], testSet.sig)).toBeBoolean();
    });
    describe("should default to false", () => {
      it("should handle invalid message", () => {
        expect(aggregateVerify([sullyUint8Array(testSet.msg)], [testSet.pk], testSet.sig)).toBeFalse();
      });
    });
    it("should return true for valid sets", () => {
      expect(aggregateVerify([testSet.msg], [testSet.pk], testSet.sig)).toBeTrue();
    });
  });
});

describe("Fast Aggregate Verify", () => {
  let testSet: TestSet;
  beforeAll(() => {
    testSet = getTestSet();
  });
  describe("fastAggregateVerify", () => {
    it("should return a boolean", () => {
      expect(fastAggregateVerify(testSet.msg, [testSet.pk], testSet.sig)).toBeBoolean();
    });
    describe("should default to false", () => {
      it("should handle invalid message", () => {
        expect(fastAggregateVerify(sullyUint8Array(testSet.msg), [testSet.pk], testSet.sig)).toBeFalse();
      });
    });
    it("should return true for valid sets", () => {
      expect(fastAggregateVerify(testSet.msg, [testSet.pk], testSet.sig)).toBeTrue();
    });
  });
});

afterAll(() => {
  // TODO: enable this on all tests cause "segmentation fault" on CI
  // closeBinding();
});