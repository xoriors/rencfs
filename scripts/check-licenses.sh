#!/bin/bash
set -eo pipefail

# install dependencies (useful for local checking)
command -v jq >/dev/null || sudo apt-get install -y jq
command -v cargo-license >/dev/null || cargo install cargo-license

echo "Validating licenses..."

# names of packages to exclude from check
WHITELIST=("ring")

ALLOWED_LICENSES="MIT|Apache-2.0|BSD-3-Clause|Unlicense"

# find packages with disallowed licenses
DISALLOWED=$(cargo license --all-features --direct-deps-only --json |
  jq -r '.[] | "\(.name)\t\(.license // "NULL")"' |
  while IFS=$'\t' read -r name license; do
    if [[ " ${WHITELIST[*]} " =~ " $name " ]]; then
      continue
    fi
    
    if [[ "$license" == "NULL" || ! "$license" =~ $ALLOWED_LICENSES ]]; then
      echo "$name ($license)"
    fi
  done
)

if [ -n "$DISALLOWED" ]; then
  echo "Disallowed licenses found:"
  echo "$DISALLOWED"
  exit 1
fi

# generate THIRD-PARTY-LICENSES.md
echo -e "# THIRD PARTY LICENSES:\n" > docs/THIRD-PARTY-LICENSES.md
cargo license --all-features --direct-deps-only --json |
  jq -r '
    .[] | 
    "## \(.name)\n" +
    "- Version: \(.version)\n" +
    "- License: \(.license // "UNKNOWN")\n" +
    "- Repository: \(.repository // "")\n"
  ' >> docs/THIRD-PARTY-LICENSES.md

# copy license specific files
mkdir -p docs/third-party-licenses
cargo vendor --versioned-dirs vendor >/dev/null 2>&1
find vendor -type f \
    \( -iname 'LICENSE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) \
    -exec cp --parents {} docs/third-party-licenses/ \;

# cleanup
rm -rf vendor

echo "License check passed"
