import { existsSync } from "fs";
import { getBinaryName, getPrebuiltBinaryPath } from "../utils";

// CLI runner and entrance for this file when called by npm/yarn
install().then(
	() => process.exit(0),
	(e) => {
		console.error(e);
		process.exit(1);
	},
);

async function install(): Promise<void> {
	const binaryName = getBinaryName();
	let binaryPath: string | undefined = getPrebuiltBinaryPath(binaryName);

	// Check if bindings already bundled, downloaded or built
	if (existsSync(binaryPath)) {
		console.log(`Found prebuilt bindings at ${binaryPath}`);
		return;
	}

	throw Error(`No prebuilt bindings found for ${binaryPath}`);
}
