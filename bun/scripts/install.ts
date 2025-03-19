import { createWriteStream, existsSync, mkdirSync } from "fs";
/* eslint-disable no-extra-boolean-cast */
/* eslint-disable no-console */
import { Readable } from "stream";
import { finished } from "stream/promises";
import type { ReadableStream } from "stream/web";
import { PREBUILD_DIR, getBinaryName, getPrebuiltBinaryPath } from "../utils";

const VERSION = "0.1.0-rc.4";

// CLI runner and entrance for this file when called by npm/yarn
install().then(
	() => process.exit(0),
	(e) => {
		console.error(e);
		process.exit(1);
	},
);

function getReleaseUrl(binaryName: string): string {
	return `https://github.com/ChainSafe/blst-z/releases/download/v${VERSION}/${binaryName}`;
}

/**
 * Download bindings from GitHub release
 */
async function downloadBindings(binaryName: string): Promise<string> {
	const url = getReleaseUrl(binaryName);
	console.log(`Downloading bindings from ${url}`);
	const { body, status } = await fetch(url);

	if (!body || status >= 400) {
		throw new Error("Failed to download bindings");
	}

	if (!existsSync(PREBUILD_DIR)) {
		mkdirSync(PREBUILD_DIR, { recursive: true });
	}

	const outputPath = getPrebuiltBinaryPath(binaryName);

	await finished(
		Readable.fromWeb(body as ReadableStream<Uint8Array>).pipe(
			createWriteStream(outputPath),
		),
	);

	return outputPath;
}

async function install(): Promise<void> {
	const binaryName = getBinaryName();
	let binaryPath: string | undefined = getPrebuiltBinaryPath(binaryName);

	// Check if bindings already bundled, downloaded or built
	if (existsSync(binaryPath)) {
		console.log(`Found prebuilt bindings at ${binaryPath}`);
		return;
	}

	console.log(`No prebuilt bindings found for ${binaryName}`);

	// Fetch pre-built bindings from remote repo
	try {
		binaryPath = await downloadBindings(binaryName);
	} catch {
		throw Error(`Could not download bindings file. Tried:\n${binaryPath}`);
	}

	if (existsSync(binaryPath)) {
		console.log(`Downloaded github release bindings to ${binaryPath}`);
	} else {
		throw Error(`Could not find bindings file. Tried:\n${binaryPath}`);
	}
}
