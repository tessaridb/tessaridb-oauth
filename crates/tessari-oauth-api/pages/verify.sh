#!/usr/bin/env bash
# The pages' build output is committed, so it can drift from its source two
# ways: a hand-edit under crates/tessari-oauth-api/assets/, or a source edit with
# no rebuild. Neither fails anything else. The build is deterministic, so
# running it must leave the asset BYTES exactly as they were.
set -euo pipefail

pages="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(git -C "$pages" rev-parse --show-toplevel)"
assets="crates/tessari-oauth-api/assets"

if [ ! -d "$pages/node_modules" ]; then
  echo "pages: node_modules is missing; run 'npm install' in $pages" >&2
  exit 2
fi

fingerprint() { find "$root/$assets" -type f -exec shasum {} + | sed "s|$root/||" | sort; }

before="$(fingerprint)"
( cd "$pages" && npm run --silent typecheck && npm run --silent test && npm run --silent build )
after="$(fingerprint)"

if [ "$before" != "$after" ]; then
  echo "pages: the committed assets do not match what the source builds." >&2
  echo "       Re-run the build and commit the result, or revert the hand-edit." >&2
  exit 1
fi
echo "pages: committed assets match the source"
