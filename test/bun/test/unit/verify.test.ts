import {afterAll, beforeAll, describe, expect, it} from "bun:test";

import {aggregateVerify, fastAggregateVerify, verify} from "../../src/verify.js";
import {sullyUint8Array} from "../utils/helpers.js";
import {getTestSet} from "../utils/testSets.js";
import type {TestSet} from "../utils/types.js";
import { aggregateSignatures } from "../../src/aggregate.js";

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
    it.only("fuzzy test - aggregateVerify()", () => {
      const testSets: TestSet[] = [];
      for (let i = 0; i < 128; i++) {
        testSets.push(getTestSet());
      }
      const msgs = testSets.map((set) => set.msg);
      const pks = testSets.map((set) => set.pk);
      const sigs = testSets.map((set) => set.sig);
      const aggSig = aggregateSignatures(sigs);

      let count = 0;
      while (true) {
        const now = Date.now();
        for (let i = 0; i < 1000; i ++) {
          expect(aggregateVerify(msgs, pks, aggSig)).toBeTrue();
        }
        console.log("aggregateVerify() took", Date.now() - now, "ms", count);
        count++;
      }
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
