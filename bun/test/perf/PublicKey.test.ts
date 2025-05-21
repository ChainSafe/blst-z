import {describe} from "@chainsafe/benchmark";
import {bench} from "@chainsafe/benchmark";
import * as blst from "../../src/index.js";
import {arrayOfIndexes} from "../utils/helpers.js";
import {getSerializedTestSet, getTestSet} from "../utils/testSets.js";

const napiTestKey = getTestSet(0).pk;

describe("PublicKey", () => {
	bench("PublicKey serialization", () => {
		napiTestKey.toBytes();
	});

	bench({
		id: "PublicKey deserialize",
		beforeEach: () => napiTestKey.toBytes(),
		fn: (serialized) => {
			blst.PublicKey.fromBytes(serialized, false);
		},
	});

	for (const count of [1, 100, 10_000]) {
		bench({
			id: `PublicKey deserialize and validate - ${count} keys`,
			beforeEach: () => arrayOfIndexes(0, count - 1).map((i) => getSerializedTestSet(i % 256).pk),
			fn: (publicKeys) => {
				for (const publicKey of publicKeys) {
					blst.PublicKey.fromBytes(publicKey, true);
				}
			},
		});
	}
});
