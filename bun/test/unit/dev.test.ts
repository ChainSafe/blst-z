import {beforeAll, describe, expect, it} from "bun:test";
import {asyncAggregateWithRandomness, asyncTest} from "../../src/aggregateWithRandomness.js";
import {G1_POINT_AT_INFINITY, G2_POINT_AT_INFINITY} from "../__fixtures__/index.js";
import {getTestSet, getTestSetsSameMessage} from "../utils/testSets.js";

// describe("Aggregate With Randomness", () => {
// 	const sameMessageSets = getTestSetsSameMessage(10);
// 	// const msg = sameMessageSets.msg;
// 	const sets = sameMessageSets.sets.map((s) => ({
// 		pk: s.pk,
// 		sig: s.sig.toBytes(),
// 	}));
// 	// const randomSet = getTestSet(20);
// 	// const infinityPublicKey = Buffer.from(G1_POINT_AT_INFINITY, "hex");

// 	it("should throw for invalid serialized", async () => {
// 		try {
// 			await asyncAggregateWithRandomness(
// 				sets.concat({
// 					pk: sets[0].pk,
// 					//TODO: (@matthewkeil) this throws error "Public key is infinity" not signature because there is only one blst error
// 					sig: G2_POINT_AT_INFINITY,
// 				} as any)
// 			);
// 			expect.fail("should not get here");
// 		} catch (err) {
// 			expect((err as Error).message).toEqual("Failed to aggregate with randomness");
// 		}
// 	});
// });

it("simplest async test", async () => {
  expect(await asyncTest(0)).toEqual(0);
  expect(await asyncTest(1)).toEqual(1);
});