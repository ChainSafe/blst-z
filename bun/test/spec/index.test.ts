import {beforeAll, describe, expect, it} from "bun:test";
import {testFnByName} from "./functions.js";
import {type TestBatchMeta, getTestBatch} from "./utils.js";

const testLocations: TestBatchMeta[] = [
	{directory: "spec-tests/tests/general/phase0/bls", innerBlsFolder: true},
	{directory: "spec-tests/tests/general/altair/bls", innerBlsFolder: true},
	{directory: "spec-tests-bls", namedYamlFiles: true},
];

const skippedFunctions: string[] = ["hash_to_G2"];

const skippedTestCaseNames: string[] = [
	// TODO: BLS dealing of the Infinity public key does not allow to validate `infinity_with_true_b_flag`.
	// This _should_ not have any impact of Beacon Chain in production, so it's ignored until fixed upstream
	"deserialization_succeeds_infinity_with_true_b_flag",
];

(function runTests(): void {
	const batches = testLocations.map(getTestBatch);
	for (const {directory, testGroups: tests} of batches) {
		describe(directory, () => {
			for (const {functionName, testCases} of tests) {
				if (skippedFunctions.includes(functionName)) continue;
				describe(functionName, () => {
					const testFn = testFnByName[functionName];
					beforeAll(() => {
						if (!testFn) throw Error(`Unknown test function: ${functionName}`);
					});

					for (const {testCaseName, testCaseData} of testCases) {
						if (skippedTestCaseNames.includes(testCaseName)) {
							continue;
						}
						if (process.env.DEBUG) {
							console.log(testCaseData);
						}
						it(testCaseName, () => {
							if (testCaseData.output === null) {
								// eslint-disable-next-line @typescript-eslint/no-unsafe-return
								expect(() => testFn(testCaseData.input)).toThrow();
							} else {
								expect(testFn(testCaseData.input)).toEqual(testCaseData.output);
							}
						});
					}
				});
			}
		});
	}
})();
