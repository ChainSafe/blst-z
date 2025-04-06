import {describe} from "@chainsafe/benchmark";
import {bench} from "@chainsafe/benchmark";
import * as blst from "../../src/index.js";
import {commonMessage, getTestSet} from "../utils/testSets.js";

const napiTestKey = getTestSet(0).sk;

describe("SecretKey", () => {
	const ikm = Buffer.alloc(32, 1);
	bench("SecretKey.fromKeygen", () => {
		blst.SecretKey.fromKeygen(ikm);
	});

	bench("SecretKey serialization", () => {
		napiTestKey.toBytes();
	});

	bench({
		id: "SecretKey deserialization",
		beforeEach: () => napiTestKey.toBytes(),
		fn: (serialized) => {
			blst.SecretKey.fromBytes(serialized);
		},
	});

	bench("SecretKey.toPublicKey", () => {
		napiTestKey.toPublicKey();
	});

	bench("SecretKey.sign", () => {
		napiTestKey.sign(commonMessage);
	});
});
