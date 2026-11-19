#!/usr/bin/env bash
# Build an installable plugin ZIP from the current checkout WITHOUT touching it.
# Used by CI to give feature branches and pull requests a testable artifact.
#
# Usage: build-dev-zip.sh <version> <output.zip>
set -euo pipefail

VERSION="${1:?version required}"
OUTPUT="${2:?output zip path required}"
PLUGIN_DIR="keystone-oidc"
# Resolve to an absolute path before changing directory (portable, no realpath -m).
mkdir -p "$(dirname "${OUTPUT}")"
OUTPUT="$(cd "$(dirname "${OUTPUT}")" && pwd)/$(basename "${OUTPUT}")"
STAGING="$(mktemp -d)"
trap 'rm -rf "${STAGING}"' EXIT

mkdir -p "${STAGING}/${PLUGIN_DIR}"
# Keep this exclude list in sync with the "Create plugin ZIP" step in _release.yml.
rsync -a \
  --exclude='.git' \
  --exclude='.github' \
  --exclude='assets' \
  --exclude='.gitignore' \
  --exclude='docs' \
  --exclude='docs-site' \
  --exclude='*.zip' \
  ./ "${STAGING}/${PLUGIN_DIR}/"

# Stamp the version into the copy only, so a dev build is recognisable in wp-admin.
sed -i "s/^ \* Version:.*/ * Version: ${VERSION}/" "${STAGING}/${PLUGIN_DIR}/keystone-oidc.php"
sed -i "s/define( 'KEYSTONE_OIDC_VERSION', '[^']*' )/define( 'KEYSTONE_OIDC_VERSION', '${VERSION}' )/" "${STAGING}/${PLUGIN_DIR}/keystone-oidc.php"
sed -i "s/^Stable tag:.*/Stable tag: ${VERSION}/" "${STAGING}/${PLUGIN_DIR}/readme.txt"

rm -f "${OUTPUT}"
(cd "${STAGING}" && zip -qr "${OUTPUT}" "${PLUGIN_DIR}")
echo "Created ${OUTPUT}"
