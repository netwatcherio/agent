#!/bin/bash

# NetWatcher Agent Installation Script
# This script downloads, installs, and configures the NetWatcher Agent as a systemd service

set -e  # Exit on any error

# Configuration
GITHUB_REPO="netwatcherio/agent"
INSTALL_DIR="/opt/netwatcher-agent"
SERVICE_NAME="netwatcher-agent"
CONFIG_FILE="config.conf"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_NAME="netwatcher-agent"

# Default values
DEFAULT_HOST="https://api.netwatcher.io"
DEFAULT_HOST_WS="wss://api.netwatcher.io/agent_ws"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_debug() {
    if [[ "$DEBUG" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" >&2
    fi
}

# Show usage information
show_usage() {
    cat << EOF
NetWatcher Agent Installation Script

Usage: $0 --id <AGENT_ID> --pin <AGENT_PIN> [OPTIONS]

Required Arguments:
    --id, -i <AGENT_ID>     Agent ID (MongoDB ObjectID format)
    --pin, -p <AGENT_PIN>   Agent PIN

Optional Arguments:
    --host <HOST>           API host (default: $DEFAULT_HOST)
    --host-ws <HOST_WS>     WebSocket host (default: $DEFAULT_HOST_WS)
    --install-dir <DIR>     Installation directory (default: $INSTALL_DIR)
    --force                 Force reinstallation even if already installed
    --no-service            Skip systemd service creation
    --no-start              Don't start the service after installation
    --version <VERSION>     Install specific version (default: latest)
    --debug                 Enable debug output
    --help, -h              Show this help message

Examples:
    # Basic installation
    $0 --id 686c6d4298d36e8a13fb7ee6 --pin 036977322

    # Custom host configuration
    $0 --id 686c6d4298d36e8a13fb7ee6 --pin 036977322 \\
       --host https://api.netwatcher.io --host-ws wss://api.netwatcher.io/agent_ws

    # Install to custom directory
    $0 --id 686c6d4298d36e8a13fb7ee6 --pin 036977322 --install-dir /usr/local/netwatcher

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --id|-i)
                AGENT_ID="$2"
                shift 2
                ;;
            --pin|-p)
                AGENT_PIN="$2"
                shift 2
                ;;
            --host)
                HOST="$2"
                shift 2
                ;;
            --host-ws)
                HOST_WS="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --force)
                FORCE_INSTALL=true
                shift
                ;;
            --no-service)
                NO_SERVICE=true
                shift
                ;;
            --no-start)
                NO_START=true
                shift
                ;;
            --debug)
                DEBUG=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Set defaults if not provided
    HOST=${HOST:-$DEFAULT_HOST}
    HOST_WS=${HOST_WS:-$DEFAULT_HOST_WS}
    FORCE_INSTALL=${FORCE_INSTALL:-false}
    NO_SERVICE=${NO_SERVICE:-false}
    NO_START=${NO_START:-false}
    DEBUG=${DEBUG:-false}
}

# Validate required arguments
validate_arguments() {
    if [[ -z "$AGENT_ID" ]]; then
        log_error "Agent ID is required. Use --id or -i to specify it."
        show_usage
        exit 1
    fi

    if [[ -z "$AGENT_PIN" ]]; then
        log_error "Agent PIN is required. Use --pin or -p to specify it."
        show_usage
        exit 1
    fi

    # Validate Agent ID format (MongoDB ObjectID - 24 hex characters)
    if [[ ! "$AGENT_ID" =~ ^[0-9a-fA-F]{24}$ ]]; then
        log_error "Invalid Agent ID format. Expected 24 hexadecimal characters."
        exit 1
    fi

    # Validate PIN format (should be numeric)
    if [[ ! "$AGENT_PIN" =~ ^[0-9]+$ ]]; then
        log_error "Invalid PIN format. Expected numeric value."
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect system architecture
detect_architecture() {
    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')

    case $arch in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="arm"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    case $os in
        linux)
            OS="linux"
            ;;
        darwin)
            OS="darwin"
            ;;
        *)
            log_error "Unsupported operating system: $os"
            exit 1
            ;;
    esac

    log_info "Detected platform: ${OS}-${ARCH}"
}

# Get latest release version from GitHub
get_latest_version() {
    if [[ -n "$VERSION" ]]; then
        log_info "Using specified version: $VERSION"
        return
    fi

    log_info "Fetching latest release information..."

    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response=$(curl -s "$api_url")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to fetch release information from GitHub"
        exit 1
    fi

    VERSION=$(echo "$response" | grep -o '"tag_name": *"[^"]*"' | cut -d'"' -f4)

    if [[ -z "$VERSION" ]]; then
        log_error "Could not determine latest version"
        exit 1
    fi

    log_info "Latest version: $VERSION"
}

# Get available assets for a release
get_release_assets() {
    local version="$1"
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${version}"

    log_debug "Fetching release assets from: $api_url"

    local response
    local curl_exit_code

    response=$(curl -s -w "HTTPSTATUS:%{http_code}" --max-time 30 "$api_url" 2>&1)
    curl_exit_code=$?

    if [[ $curl_exit_code -ne 0 ]]; then
        log_error "Failed to fetch release assets"
        return 1
    fi

    local http_status
    if [[ "$response" =~ HTTPSTATUS:([0-9]+) ]]; then
        http_status="${BASH_REMATCH[1]}"
    else
        log_error "Could not parse HTTP status from assets response"
        return 1
    fi

    local body=$(echo "$response" | sed 's/HTTPSTATUS:[0-9]*$//')

    if [[ "$http_status" != "200" ]]; then
        log_error "GitHub API returned status $http_status when fetching assets"
        return 1
    fi

    # Extract asset names - only output to stdout, no debug messages here
    if command -v jq > /dev/null 2>&1; then
        echo "$body" | jq -r '.assets[].name' 2>/dev/null
    else
        echo "$body" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
    fi
}

# Find the best matching asset for current platform
find_matching_asset() {
    local version="$1"
    local assets="$2"

    log_debug "Available assets:"
    echo "$assets" | while read -r asset; do
        log_debug "  - $asset"
    done >&2

    # Platform identifiers to look for
    local os_patterns=()
    local arch_patterns=()

    case "$OS" in
        "linux")
            os_patterns=("linux" "Linux")
            ;;
        "darwin")
            os_patterns=("darwin" "macos" "macOS" "mac" "osx")
            ;;
        "windows")
            os_patterns=("windows" "win" "Windows")
            ;;
    esac

    case "$ARCH" in
        "amd64")
            arch_patterns=("amd64" "x86_64" "x64" "64bit" "64-bit")
            ;;
        "arm64")
            arch_patterns=("arm64" "aarch64" "arm_64")
            ;;
        "arm")
            arch_patterns=("arm" "armv7" "armhf")
            ;;
    esac

    # Score each asset based on how well it matches our platform
    local best_asset=""
    local best_score=0

    while IFS= read -r asset; do
        [[ -z "$asset" ]] && continue

        local score=0
        local asset_lower=$(echo "$asset" | tr '[:upper:]' '[:lower:]')

        # Check OS patterns
        for pattern in "${os_patterns[@]}"; do
            if [[ "$asset_lower" == *"$(echo "$pattern" | tr '[:upper:]' '[:lower:]')"* ]]; then
                score=$((score + 10))
                break
            fi
        done

        # Check architecture patterns
        for pattern in "${arch_patterns[@]}"; do
            if [[ "$asset_lower" == *"$(echo "$pattern" | tr '[:upper:]' '[:lower:]')"* ]]; then
                score=$((score + 10))
                break
            fi
        done

        # Prefer certain file extensions
        if [[ "$asset" == *.tar.gz ]]; then
            score=$((score + 5))
        elif [[ "$asset" == *.zip ]]; then
            score=$((score + 3))
        elif [[ "$asset" == *.exe ]] && [[ "$OS" == "windows" ]]; then
            score=$((score + 5))
        fi

        # Avoid source code archives
        if [[ "$asset" == *"source"* ]] || [[ "$asset" == *"src"* ]]; then
            score=$((score - 5))
        fi

        log_debug "Asset: $asset, Score: $score"

        if [[ $score -gt $best_score ]]; then
            best_score=$score
            best_asset="$asset"
        fi
    done <<< "$assets"

    if [[ -n "$best_asset" ]]; then
        log_debug "Best matching asset: $best_asset (score: $best_score)"
        echo "$best_asset"
        return 0
    else
        log_debug "No suitable asset found"
        return 1
    fi
}

download_and_install() {
    # First, get the list of available assets
    log_info "Fetching available assets for version $VERSION..."
    local assets=$(get_release_assets "$VERSION")

    if [[ -z "$assets" ]]; then
        log_error "No assets found for version $VERSION"
        exit 1
    fi

    # Find the best matching asset for our platform
    local asset_name=$(find_matching_asset "$VERSION" "$assets")

    if [[ -z "$asset_name" ]]; then
        log_error "No suitable asset found for platform ${OS}-${ARCH}"
        log_error "Available assets:"
        echo "$assets" | while read -r asset; do
            echo "  - $asset"
        done
        exit 1
    fi

    log_info "Selected asset: $asset_name"

    # Construct the download URL
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${asset_name}"

    # Create installation directory
    log_info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"

    # Download the release
    local temp_file=$(mktemp)
    log_info "Downloading NetWatcher Agent from: $download_url"

    if ! curl -L -f -o "$temp_file" "$download_url"; then
        log_error "Failed to download release from: $download_url"
        rm -f "$temp_file"
        exit 1
    fi

    # Extract or copy based on file type
    local binary_path="${INSTALL_DIR}/${BINARY_NAME}"

    if [[ "$asset_name" == *.tar.gz ]]; then
        log_info "Extracting tar.gz archive..."
        tar -xzf "$temp_file" -C "$INSTALL_DIR"
    elif [[ "$asset_name" == *.zip ]]; then
        log_info "Extracting zip archive..."
        unzip -q -o "$temp_file" -d "$INSTALL_DIR"
    else
        log_info "Installing direct binary..."
        cp "$temp_file" "$binary_path"
    fi

    # Find the actual binary - it might be named differently
    local found_binary=""

    # First, check if binary exists at expected location
    if [[ -f "$binary_path" ]]; then
        found_binary="$binary_path"
    else
        # Search for executable files that might be the agent
        log_debug "Searching for binary in $INSTALL_DIR..."

        # Look for common variations of the binary name
        for name in "netwatcher-agent" "netwatcher" "agent" "netwatcher-*"; do
            local candidate=$(find "$INSTALL_DIR" -name "$name" -type f -executable 2>/dev/null | head -1)
            if [[ -n "$candidate" ]]; then
                found_binary="$candidate"
                log_debug "Found binary: $candidate"
                break
            fi
        done

        # If still not found, look for any executable file
        if [[ -z "$found_binary" ]]; then
            found_binary=$(find "$INSTALL_DIR" -type f -executable 2>/dev/null | grep -v '\.sh$' | head -1)
            if [[ -n "$found_binary" ]]; then
                log_debug "Found executable: $found_binary"
            fi
        fi

        # Move the found binary to expected location if different
        if [[ -n "$found_binary" ]] && [[ "$found_binary" != "$binary_path" ]]; then
            log_debug "Moving $found_binary to $binary_path"
            mv "$found_binary" "$binary_path"
            found_binary="$binary_path"
        fi
    fi

    # Make binary executable
    if [[ -n "$found_binary" ]]; then
        chmod +x "$found_binary"
    fi

    # Clean up
    rm -f "$temp_file"

    # Verify installation
    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found after installation: $binary_path"
        log_error "Contents of $INSTALL_DIR:"
        ls -la "$INSTALL_DIR" >&2
        exit 1
    fi

    log_success "NetWatcher Agent installed to: $binary_path"
}

# Create configuration file
create_config() {
    local config_path="${INSTALL_DIR}/${CONFIG_FILE}"

    log_info "Creating configuration file: $config_path"

    cat > "$config_path" << EOF
# NetWatcher Agent Configuration
HOST=$HOST
HOST_WS=$HOST_WS
ID=$AGENT_ID
PIN=$AGENT_PIN
EOF

    # Set appropriate permissions
    chmod 600 "$config_path"

    log_success "Configuration file created"
}

# Create systemd service file
create_service() {
    if [[ "$NO_SERVICE" == true ]]; then
        log_info "Skipping systemd service creation"
        return
    fi

    log_info "Creating systemd service file: $SERVICE_FILE"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=NetWatcher Agent Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --config ${INSTALL_DIR}/${CONFIG_FILE}
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
User=root
Group=root

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR}

# Environment
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    log_info "Reloading systemd daemon..."
    systemctl daemon-reload

    log_info "Enabling NetWatcher Agent service..."
    systemctl enable "$SERVICE_NAME"

    log_success "Systemd service created and enabled"
}

# Start the service
start_service() {
    if [[ "$NO_SERVICE" == true ]] || [[ "$NO_START" == true ]]; then
        log_info "Skipping service startup"
        return
    fi

    log_info "Starting NetWatcher Agent service..."

    if systemctl start "$SERVICE_NAME"; then
        log_success "NetWatcher Agent service started successfully"

        # Wait a moment and check status
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_success "Service is running"
        else
            log_warning "Service may have failed to start. Check logs with: journalctl -u $SERVICE_NAME"
        fi
    else
        log_error "Failed to start NetWatcher Agent service"
        log_info "Check logs with: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

# Check if already installed
check_existing_installation() {
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]] && [[ "$FORCE_INSTALL" != true ]]; then
        log_warning "NetWatcher Agent is already installed at $INSTALL_DIR"
        log_info "Use --force to reinstall"

        # Check if service is running
        if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
            log_info "Service is currently running"
            log_info "To restart: sudo systemctl restart $SERVICE_NAME"
        fi

        exit 0
    fi
}

# Stop existing service if running
stop_existing_service() {
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping existing NetWatcher Agent service..."
        systemctl stop "$SERVICE_NAME"
    fi
}

# Install required dependencies
install_dependencies() {
    log_info "Checking dependencies..."

    local deps=("curl" "tar" "unzip")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" > /dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_info "Installing missing dependencies: ${missing_deps[*]}"

        if command -v apt-get > /dev/null 2>&1; then
            apt-get update && apt-get install -y "${missing_deps[@]}"
        elif command -v yum > /dev/null 2>&1; then
            yum install -y "${missing_deps[@]}"
        elif command -v dnf > /dev/null 2>&1; then
            dnf install -y "${missing_deps[@]}"
        elif command -v pacman > /dev/null 2>&1; then
            pacman -S --noconfirm "${missing_deps[@]}"
        else
            log_error "Could not install dependencies. Please install manually: ${missing_deps[*]}"
            exit 1
        fi
    fi
}

# Show installation summary
show_summary() {
    log_success "NetWatcher Agent installation completed!"
    echo
    log_info "Installation Details:"
    echo "  - Binary: ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  - Config: ${INSTALL_DIR}/${CONFIG_FILE}"
    echo "  - Service: $SERVICE_NAME"
    echo "  - Version: $VERSION"
    echo
    log_info "Useful Commands:"
    echo "  - Check status: sudo systemctl status $SERVICE_NAME"
    echo "  - View logs: sudo journalctl -u $SERVICE_NAME -f"
    echo "  - Restart: sudo systemctl restart $SERVICE_NAME"
    echo "  - Stop: sudo systemctl stop $SERVICE_NAME"
    echo "  - Disable: sudo systemctl disable $SERVICE_NAME"
    echo
    if [[ "$NO_SERVICE" != true ]]; then
        log_info "The NetWatcher Agent is now running and will start automatically on boot."
    fi
}

# Main execution
main() {
    echo "NetWatcher Agent Installation Script"
    echo "===================================="
    echo

    parse_arguments "$@"
    validate_arguments
    check_root
    detect_architecture
    install_dependencies
    check_existing_installation
    stop_existing_service
    get_latest_version
    download_and_install
    create_config
    create_service
    start_service
    show_summary
}

# Run main function with all arguments
main "$@"