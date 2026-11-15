#!/usr/bin/env bash
set -euo pipefail

# Tag builds use the tag (nfpm strips a leading "v"). Everything else gets a
# semver pre-release, because deb versions must start with a digit and a bare
# commit hash often doesn't.
if [[ "${GITHUB_REF-}" =~ ^refs/tags/ ]]; then
  echo "${GITHUB_REF#refs/tags/}"
  exit
fi

if [[ -n "${GITHUB_SHA-}" ]]; then
  echo "0.0.0-dev.g${GITHUB_SHA:0:7}"
  exit
fi

echo "0.0.0-dev"
