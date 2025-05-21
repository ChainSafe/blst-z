import {describe} from "@chainsafe/benchmark";
import {bench} from "@chainsafe/benchmark";
import * as blst from "../../src/index.js";
import {arrayOfIndexes} from "../utils/helpers.js";
import {getSerializedTestSet, getTestSet} from "../utils/testSets.js";

const napiTestSignature = getTestSet(0).sig;

describe("Signature", () => {
	bench("Signature serialization", () => {
		napiTestSignature.toBytes();
	});

	bench({
		id: "Signature deserialize",
		beforeEach: () => napiTestSignature.toBytes(),
		fn: (serialized) => {
			blst.Signature.fromBytes(serialized);
		},
	});

	for (const count of [1, 100, 10_000]) {
		bench({
			id: `Signatures deserialize and validate - ${count} sets`,
			before() {
				return arrayOfIndexes(0, count - 1).map((i) => getSerializedTestSet(i % 256).sig);
			},
			beforeEach: (sigs) => sigs,
			fn: (signatures) => {
				for (const signature of signatures) {
					blst.Signature.fromBytes(signature, true);
				}
			},
		});
	}
});
