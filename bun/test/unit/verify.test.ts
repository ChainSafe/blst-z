import {afterAll, beforeAll, describe, expect, it} from "bun:test";

import {sullyUint8Array} from "../utils/helpers.js";
import {getTestSet} from "../utils/testSets.js";
import type {TestSet} from "../utils/types.js";

describe("Verify", () => {
	let testSet: TestSet;
	beforeAll(() => {
		testSet = getTestSet();
	});

	describe("verify", () => {
		it("should return a boolean", () => {
			expect(testSet.sig.verify(testSet.msg, testSet.pk)).toBeBoolean();
		});
		describe("should default to false", () => {
			it("should handle invalid message", () => {
				expect(testSet.sig.verify(sullyUint8Array(testSet.msg), testSet.pk)).toBeFalse();
			});
		});
		it("should return true for valid sets", () => {
			expect(testSet.sig.verify(testSet.msg, testSet.pk)).toBeTrue();
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
			expect(testSet.sig.aggregateVerify([testSet.msg], [testSet.pk])).toBeBoolean();
		});
		describe("should default to false", () => {
			it("should handle invalid message", () => {
				expect(testSet.sig.aggregateVerify([sullyUint8Array(testSet.msg)], [testSet.pk])).toBeFalse();
			});
		});
		it("should return true for valid sets", () => {
			expect(testSet.sig.aggregateVerify([testSet.msg], [testSet.pk])).toBeTrue();
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
			expect(testSet.sig.fastAggregateVerify(testSet.msg, [testSet.pk])).toBeBoolean();
		});
		describe("should default to false", () => {
			it("should handle invalid message", () => {
				const res = testSet.sig.fastAggregateVerify(sullyUint8Array(testSet.msg), [testSet.pk]);
				console.log(res);

				expect(res).toBeFalse();
			});
		});
	//	it("should return true for valid sets", () => {
	//		expect(testSet.sig.fastAggregateVerify(testSet.msg, [testSet.pk])).toBeTrue();
	//	});
	});
});

afterAll(() => {
	// TODO: enable this on all tests cause "segmentation fault" on CI
	// closeBinding();
});
