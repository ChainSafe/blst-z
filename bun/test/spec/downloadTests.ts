import {blsSpecTests, ethereumConsensusSpecsTests} from "./specTestVersioning.js";
import {downloadTests} from "./utils.js";

/* eslint-disable no-console */

for (const downloadTestOpts of [ethereumConsensusSpecsTests, blsSpecTests]) {
	downloadTests(downloadTestOpts, console.log).catch((e: Error) => {
		console.error(e);
		process.exit(1);
	});
}
