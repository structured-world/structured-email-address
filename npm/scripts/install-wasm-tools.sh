#!/usr/bin/env bash
# Install, on a Linux x86_64 GitHub runner, the two tools the WebAssembly build
# calls: the wasm-bindgen CLI at exactly the version Cargo.lock resolved (its
# schema must match the crate's), and binaryen's wasm-opt. Both come from their
# projects' release archives, checked against the published SHA-256 sums.
set -euo pipefail

BINARYEN_VERSION=version_133

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
bindgen_version="$(cargo metadata --manifest-path "$repo_root/Cargo.toml" --format-version 1 --locked |
  jq -r '.packages[] | select(.name == "wasm-bindgen") | .version')"

dest="${RUNNER_TEMP:?}/wasm-tools"
mkdir -p "$dest"
cd "$dest"

# The sum files name the archive by different paths (wasm-bindgen's under
# `gh-release/`), so only their hash field is used.
fetch() {
  local file expected
  file="$(basename "$1")"
  curl -sSfLO "$1"
  expected="$(curl -sSfL "$1.$2" | cut -d' ' -f1)"
  echo "$expected  $file" | sha256sum -c -
}

bindgen="wasm-bindgen-${bindgen_version}-x86_64-unknown-linux-musl"
fetch "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${bindgen_version}/${bindgen}.tar.gz" sha256sum
tar -xzf "${bindgen}.tar.gz"

binaryen="binaryen-${BINARYEN_VERSION}-x86_64-linux"
fetch "https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/${binaryen}.tar.gz" sha256
tar -xzf "${binaryen}.tar.gz"

echo "$dest/$bindgen" >> "$GITHUB_PATH"
echo "$dest/binaryen-${BINARYEN_VERSION}/bin" >> "$GITHUB_PATH"
