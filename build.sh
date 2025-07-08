#!/bin/bash

# Set the name of your application
APP_NAME="netwatcher-agent"

# Set the path of your main.go file
MAIN_PATH="./"

# Create a bin directory
mkdir -p bin

DATE=$(date +%Y%m%d-%H%M%S)

# Build for macOS (amd64 and arm64)
echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-darwin-amd64 ${MAIN_PATH}
GOOS=darwin GOARCH=arm64 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-darwin-arm64 ${MAIN_PATH}

# Build for Linux (amd64 and arm64)
echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-linux-amd64 ${MAIN_PATH}
GOOS=linux GOARCH=arm64 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-linux-arm64 ${MAIN_PATH}

# Build for Windows (amd64 and 386)
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-windows-amd64.exe ${MAIN_PATH}
GOOS=windows GOARCH=386 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-windows-386.exe ${MAIN_PATH}

# Build for MIPS (32-bit and 64-bit, big endian and little endian)
echo "Building for MIPS..."
GOOS=linux GOARCH=mips go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-linux-mips ${MAIN_PATH}
GOOS=linux GOARCH=mipsle go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-linux-mipsle ${MAIN_PATH}
GOOS=linux GOARCH=mips64 go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-linux-mips64 ${MAIN_PATH}
GOOS=linux GOARCH=mips64le go build -ldflags="-X main.buildDate=${DATE}" -o bin/${APP_NAME}-linux-mips64le ${MAIN_PATH}

# Create ZIP archives for each release
cd bin
for file in *; do
    if [ -f "$file" ]; then
        zip "${file}.zip" "$file"
        rm "$file"
    fi
done
cd ..

echo "Build complete. Release files are in the 'bin' directory."