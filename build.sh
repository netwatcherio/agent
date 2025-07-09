#!/bin/bash

export CGO_ENABLED=0

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
platforms=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

for platform in "${platforms[@]}"; do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}

    output_name="netwatcher-${GOOS}-${GOARCH}"
    if [ $GOOS = "windows" ]; then
        output_name+='.exe'
    fi

    echo "Building for $GOOS/$GOARCH..."

    env GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "$LDFLAGS" \
        -o "bin/${output_name}" \
        .

    if [ $? -ne 0 ]; then
        echo "Failed to build for $GOOS/$GOARCH"
        exit 1
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
sha256sum *.zip > "netwatcher-${VERSION}-checksums.txt"
cd ..

echo "Done!"