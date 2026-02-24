#!/usr/bin/env bash
set -euo pipefail

REPO="jakobhautop/opensus"
ARCH="x86_64-unknown-linux-gnu"
INSTALL_DIR="${HOME}/.local/opensus"
BIN_LINK="/usr/local/bin/opensus"

printf 'Detecting latest release for %s...\n' "$ARCH"

URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep browser_download_url \
  | grep "${ARCH}.tar.gz" \
  | cut -d '"' -f 4)

if [ -z "$URL" ]; then
  echo "No matching Linux x64 release found."
  exit 1
fi

printf 'Downloading %s\n' "$URL"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

rm -f opensus.tar.gz opensus
curl -L -o opensus.tar.gz "$URL"

echo "Extracting..."
tar -xzf opensus.tar.gz
chmod +x opensus

echo "Linking to ${BIN_LINK}"
sudo ln -sf "$INSTALL_DIR/opensus" "$BIN_LINK"

echo "Done. You can now run:"
echo "  opensus"
