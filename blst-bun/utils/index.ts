import {resolve} from "node:path";
export const BINDINGS_NAME = "libblst_min_pk";

export const ROOT_DIR = resolve(__dirname, "..");
export const PREBUILD_DIR = resolve(ROOT_DIR, "prebuild");

class NotBunError extends Error {
  constructor(missingItem: string) {
    super(`blst-bun bindings only run in a Bun context. No ${missingItem} found.`);
  }
}

/**
 * Get shared library name according to blst-z release artifacts
 * for example: https://github.com/ChainSafe/blst-z/releases/tag/v0.1.0-rc.0
 * name: libblst_min_pk_{arch}-{platform}.{ext}
 */
export function getBinaryName(): string {
  if (!process) throw new NotBunError("global object");
  let platform = process.platform;
  if (!platform) throw new NotBunError("process.platform");
  const arch = process.arch;
  if (!arch) throw new NotBunError("process.arch");
  const nodeApiVersion = process.versions.modules;
  if (!nodeApiVersion) throw new NotBunError("process.versions.modules");

  // due to platform definition in blst, the shared library is defined with arch as x86_64 or aarch64
  // see https://github.com/supranational/blst/blob/v0.3.13/build.sh#L91
  let archName: string;
  switch(arch) {
    case "x64":
      archName = "x86_64";
      break;
    case "arm64":
      archName = "aarch64";
      break;
    default:
      throw new Error(`Unsupported architecture: ${arch}`);
  }

  // as of blst-z 0.1.0, only macos and linux were supported
  // https://github.com/ChainSafe/blst-z/blob/99e878224febc3fd835bd6762fc547466172560d/.github/workflows/release.yml#L13
  let platformName: string;
  // shared library extension
  let ext: string;
  switch (platform) {
    case "darwin":
      platformName = "macos";
      ext = "dylib";
      break;
    case "linux":
      platformName = "linux";
      ext = "so";
      break;
    case "win32":
      platformName = "windows";
      ext = "dll";
      break;
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }

  return `${BINDINGS_NAME}_${archName}-${platformName}.${ext}`;
}

export function getPrebuiltBinaryPath(binaryName: string): string {
  return resolve(PREBUILD_DIR, binaryName);
}