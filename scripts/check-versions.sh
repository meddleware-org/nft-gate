#!/usr/bin/env bash
# One version for every artifact (grounding log D16): the npm package, the crate and the image.
# Fails when gateway-workers/package.json and gateway-rust/Cargo.toml differ, and, on a tag push,
# when either differs from the tag.
set -euo pipefail
cd "$(dirname "$0")/.."

npm_version="$(node -p "require('./gateway-workers/package.json').version")"
crate_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' gateway-rust/Cargo.toml | head -n 1)"

if [ "$npm_version" != "$crate_version" ]; then
  echo "::error::gateway-workers/package.json is ${npm_version} but gateway-rust/Cargo.toml is ${crate_version}"
  exit 1
fi

if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  tag_version="${GITHUB_REF_NAME#v}"
  if [ "$tag_version" != "$npm_version" ]; then
    echo "::error::tag ${GITHUB_REF_NAME} does not match the package version ${npm_version}"
    exit 1
  fi
fi

echo "versions aligned: ${npm_version}"
