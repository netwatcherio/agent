#!/bin/bash

set -e

APP_NAME="netwatcher-agent"
MAIN_PATH="./"
BIN_DIR="bin"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BIN_DIR"

PLATFORMS=(
  "darwin amd64"
  "darwin arm64"
  "linux amd64"
  "linux arm64"
  "windows amd64"
  "windows 386"
  "linux mips"
  "linux mipsle"
  "linux mips64"
  "linux mips64le"
)

echo "Starting build: ${DATE}"

for platform in "${PLATFORMS[@]}"; do
  set -- $platform
  GOOS=$1
  GOARCH=$2
  OUTPUT="${BIN_DIR}/${APP_NAME}-${GOOS}-${GOARCH}"
  [ "$GOOS" == "windows" ] && OUTPUT+=".exe"

  echo "Building for $GOOS/$GOARCH..."
  GOOS=$GOOS GOARCH=$GOARCH go build \
    -ldflags="-X main.buildDate=${DATE}" \
    -o "$OUTPUT" "$MAIN_PATH"
done

# Archive
echo "Zipping binaries..."
cd "$BIN_DIR"
for file in *; do
  if [[ -f "$file" ]]; then
    zip "${file}.zip" "$file"
    rm "$file"
  fi
done
cd ..

echo "Build complete. Zipped binaries in '$BIN_DIR'."