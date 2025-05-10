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

echo -e "All licenses approved.\n"

# prepare output paths
LICENSES_DIR="licenses"
OUTPUT_MD="THIRD-PARTY-LICENSES.md"

mkdir -p "$LICENSES_DIR"
rm -f "$OUTPUT_MD"

echo "Vendoring dependencies..."
cargo vendor --versioned-dirs vendor >/dev/null 2>&1

echo -e "# Third-Party Licenses:\n" >> "$OUTPUT_MD"

# generate output
cargo license --all-features --direct-deps-only --json | jq -c '.[]' | \
    while read -r crate; do
  NAME=$(echo "$crate" | jq -r '.name')
  VERSION=$(echo "$crate" | jq -r '.version')
  LICENSE=$(echo "$crate" | jq -r '.license // "UNKNOWN"')
  REPO=$(echo "$crate" | jq -r '.repository // "N/A"')

  echo "Processing $NAME $VERSION..."

  echo "## $NAME" >> "$OUTPUT_MD"
  echo "- Version: $VERSION" >> "$OUTPUT_MD"
  echo "- License: $LICENSE" >> "$OUTPUT_MD"
  echo "- Repository: $REPO" >> "$OUTPUT_MD"

  CRATE_DIR=$(find vendor -type d -name "${NAME}-${VERSION}" | head -n1)

  # copy files to license/ and add the paths to THIRD-PARTY-LICENSES.md
  FOUND_LICENSE="false"
  if [[ -d "$CRATE_DIR" ]]; then
    for file in "$CRATE_DIR"/{LICENSE*,COPYING*,NOTICE*}; do
      if [[ -f "$file" ]]; then
        base=$(basename "$file")
        new_name="${NAME}-${VERSION}-${base}"
        cp "$file" "${LICENSES_DIR}/${new_name}"
        echo "- License File: ${LICENSES_DIR}/${new_name}" >> "$OUTPUT_MD"
        FOUND_LICENSE="true"
      fi
    done
  fi

  if [[ "$FOUND_LICENSE" == "false" ]]; then
    echo "- License File: Not found" >> "$OUTPUT_MD"
  fi

  echo "" >> "$OUTPUT_MD"
done

# cleanup
rm -rf vendor

echo ""
echo "License report generated at /$OUTPUT_MD"
echo "Individual license files in: /$LICENSES_DIR/"
