#!/bin/bash

# Get version information
VERSION="${VERSION:-dev}"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags for version injection
LDFLAGS="-s -w \
  -X 'main.VERSION=$VERSION' \
  -X 'main.buildDate=$BUILD_DATE' \
  -X 'main.gitCommit=$GIT_COMMIT'"

echo "Building NetWatcher..."
echo "Version: $VERSION"
echo "Build Date: $BUILD_DATE"
echo "Git Commit: $GIT_COMMIT"

# Create bin directory if it doesn't exist
mkdir -p bin

# Build for different platforms
# Format: "os/arch:cgo_enabled"
# darwin requires CGO_ENABLED=1 for pcap/libpcap support
platforms=(
    "linux/amd64:0"
    "linux/arm64:0"
    "linux/arm:0"
    "darwin/amd64:1"
    "darwin/arm64:1"
    "windows/amd64:0"
    "windows/arm64:0"
)

for platform in "${platforms[@]}"; do
    # Split platform into os/arch and cgo setting
    IFS=':' read -r osarch cgo <<< "$platform"
    platform_split=(${osarch//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}

    output_name="netwatcher-${GOOS}-${GOARCH}"
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi

    echo "Building for $GOOS/$GOARCH (CGO_ENABLED=$cgo)..."

    # darwin builds with CGO require running on macOS or having cross-compile toolchain
    if [ "$cgo" = "1" ] && [ "$(uname -s)" != "Darwin" ] && [ "$GOOS" = "darwin" ]; then
        echo "  Skipping darwin build - requires macOS or cross-compile toolchain"
        echo "  Build darwin binaries on a Mac or macOS CI runner"
        continue
    fi

    env CGO_ENABLED=$cgo GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "$LDFLAGS" \
        -o "bin/${output_name}" \
        .

    if [ $? -ne 0 ]; then
        echo "Failed to build for $GOOS/$GOARCH"
        # Don't exit on darwin failure when cross-compiling - just warn
        if [ "$GOOS" = "darwin" ]; then
            echo "  darwin build failed - this is expected when cross-compiling from Linux"
            continue
        fi
        exit 1
    fi

    # Sign darwin binaries (required for macOS to run them)
    if [ "$GOOS" = "darwin" ]; then
        echo "Code signing darwin binary..."
        codesign -s - -f "bin/${output_name}" 2>/dev/null || echo "  Warning: codesign not available (run on macOS to sign)"
    fi

    # Create zip file for this platform
    echo "Creating zip for $GOOS/$GOARCH..."
    cd bin
    zip_name="netwatcher-${VERSION}-${GOOS}-${GOARCH}.zip"
    zip "$zip_name" "$output_name"
    rm "$output_name"  # Remove the binary after zipping
    cd ..
done

echo "Build complete! All binaries are in the bin/ directory"

# Create a checksums file
cd bin
echo "Generating checksums..."
if ls *.zip 1> /dev/null 2>&1; then
    sha256sum *.zip > "netwatcher-${VERSION}-checksums.txt" 2>/dev/null || shasum -a 256 *.zip > "netwatcher-${VERSION}-checksums.txt"
fi
cd ..

echo "Done!"