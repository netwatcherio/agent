#!/bin/bash

set -e

# Configuration
GITHUB_REPO="netwatcherio/agent"
BINARY_NAME="netwatcher-agent"

# Default values
DEFAULT_HOST="https://api.netwatcher.io"
DEFAULT_HOST_WS="wss://api.netwatcher.io/agent_ws"

INSTALL_DIR="$HOME/netwatcher-agent"
SERVICE_NAME="io.netwatcher.agent"
CONFIG_FILE="config.conf"
LAUNCHD_PLIST="${SERVICE_NAME}.plist"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

show_usage() {
    cat << EOF
NetWatcher Agent macOS Installation Script

Usage: $0 --workspace <WORKSPACE_ID> --id <AGENT_ID> --pin <AGENT_PIN> [OPTIONS]
       $0 --uninstall [--force] [--install-dir <DIR>]
       $0 --update [--version <VERSION>] [--install-dir <DIR>]

Required Arguments (for installation):
    --workspace, -w <WORKSPACE_ID>  Workspace ID
    --id, -i <AGENT_ID>             Agent ID
    --pin, -p <AGENT_PIN>           Agent PIN

Optional Arguments:
    --host <HOST>           Controller host (default: api.netwatcher.io)
    --ssl <true|false>      Use SSL/HTTPS (default: true)
    --install-dir <DIR>     Installation directory (default: ~/netwatcher-agent)
    --system                Install as system-wide launchd service (requires sudo)
    --user                  Install as user-level launchd service (default, no sudo)
    --boot-service          Install as system-wide boot service (auto-starts at boot, hidden from Dock, requires sudo)
    --force                 Force reinstallation or skip uninstall confirmation
    --no-service            Skip launchd service creation
    --no-start              Don't start the service after installation
    --version <VERSION>     Install specific version (default: latest)
    --uninstall             Uninstall the agent instead of installing
    --update                Update only the binary (keeps config/service)
    --debug                 Enable debug output
    --help, -h              Show this help message

Examples:
    # Boot service installation (auto-starts at boot, recommended for root)
    sudo $0 --workspace 1 --id 42 --pin 123456789

    # User-level installation (starts at login, no sudo)
    $0 --workspace 1 --id 42 --pin 123456789 --user

    # Update binary only
    $0 --update

    # Uninstall
    $0 --uninstall

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --workspace|-w)
                WORKSPACE_ID="$2"
                shift 2
                ;;
            --id|-i)
                AGENT_ID="$2"
                shift 2
                ;;
            --pin|-p)
                AGENT_PIN="$2"
                shift 2
                ;;
            --host)
                CONTROLLER_HOST="$2"
                shift 2
                ;;
            --ssl)
                CONTROLLER_SSL="$2"
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
            --system)
                SYSTEM_LEVEL=true
                shift
                ;;
            --user)
                SYSTEM_LEVEL=false
                shift
                ;;
            --boot-service)
                BOOT_SERVICE=true
                SYSTEM_LEVEL=true
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
            --uninstall)
                UNINSTALL_MODE=true
                shift
                ;;
            --update)
                UPDATE_MODE=true
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

    CONTROLLER_HOST=${CONTROLLER_HOST:-"$DEFAULT_HOST"}
    CONTROLLER_SSL=${CONTROLLER_SSL:-"true"}
    FORCE_INSTALL=${FORCE_INSTALL:-false}
    SYSTEM_LEVEL=${SYSTEM_LEVEL:-false}
    NO_SERVICE=${NO_SERVICE:-false}
    NO_START=${NO_START:-false}
    UNINSTALL_MODE=${UNINSTALL_MODE:-false}
    UPDATE_MODE=${UPDATE_MODE:-false}
    DEBUG=${DEBUG:-false}

    if [[ "$BOOT_SERVICE" == true ]]; then
        SYSTEM_LEVEL=true
    elif [[ -w "/Library/LaunchDaemons" ]] && [[ "$BOOT_SERVICE" != false ]]; then
        log_info "Running as root - enabling boot service for automatic startup at boot"
        BOOT_SERVICE=true
        SYSTEM_LEVEL=true
    fi
}

validate_arguments() {
    if [[ -z "$WORKSPACE_ID" ]]; then
        log_error "Workspace ID is required. Use --workspace or -w to specify it."
        show_usage
        exit 1
    fi

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

    if [[ ! "$AGENT_PIN" =~ ^[0-9]+$ ]]; then
        log_error "Invalid PIN format. Expected numeric value."
        exit 1
    fi
}

detect_architecture() {
    local arch=$(uname -m)

    case $arch in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac

    OS="darwin"
    log_info "Detected platform: ${OS}-${ARCH}"
}

get_latest_version() {
    if [[ -n "$VERSION" ]]; then
        log_info "Using specified version: $VERSION"
        return
    fi

    log_info "Fetching latest release information..."

    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response=$(curl -s -H "Cache-Control: no-cache" "$api_url")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to fetch release information from GitHub"
        exit 1
    fi

    if command -v jq > /dev/null 2>&1; then
        VERSION=$(echo "$response" | jq -r '.tag_name' 2>/dev/null)
    else
        VERSION=$(echo "$response" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
    fi

    if [[ -z "$VERSION" ]]; then
        log_error "Could not determine latest version"
        exit 1
    fi

    log_info "Latest version: $VERSION"
}

get_release_assets() {
    local version="$1"
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${version}"

    local response
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" --max-time 30 "$api_url" 2>&1)

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

    if command -v jq > /dev/null 2>&1; then
        echo "$body" | jq -r '.assets[].name' 2>/dev/null
    else
        echo "$body" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
    fi
}

find_matching_asset() {
    local version="$1"
    local assets="$2"

    log_debug "Available assets:"
    echo "$assets" | while read -r asset; do
        log_debug "  - $asset"
    done >&2

    local os_patterns=("darwin" "macos" "macOS" "mac" "osx")
    local arch_patterns=()

    case "$ARCH" in
        "amd64")
            arch_patterns=("amd64" "x86_64" "x64")
            ;;
        "arm64")
            arch_patterns=("arm64" "aarch64")
            ;;
    esac

    local best_asset=""
    local best_score=0

    while IFS= read -r asset; do
        [[ -z "$asset" ]] && continue

        local score=0
        local asset_lower=$(echo "$asset" | tr '[:upper:]' '[:lower:]')

        for pattern in "${os_patterns[@]}"; do
            if [[ "$asset_lower" == *"$(echo "$pattern" | tr '[:upper:]' '[:lower:]')"* ]]; then
                score=$((score + 10))
                break
            fi
        done

        for pattern in "${arch_patterns[@]}"; do
            if [[ "$asset_lower" == *"$(echo "$pattern" | tr '[:upper:]' '[:lower:]')"* ]]; then
                score=$((score + 10))
                break
            fi
        done

        if [[ "$asset" == *.tar.gz ]]; then
            score=$((score + 5))
        elif [[ "$asset" == *.zip ]]; then
            score=$((score + 3))
        fi

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
        echo "$best_asset"
        return 0
    else
        return 1
    fi
}

download_and_install() {
    log_info "Fetching available assets for version $VERSION..."
    local assets=$(get_release_assets "$VERSION")

    if [[ -z "$assets" ]]; then
        log_error "No assets found for version $VERSION"
        exit 1
    fi

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

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${asset_name}"

    log_info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"

    local temp_file=$(mktemp)
    log_info "Downloading NetWatcher Agent from: $download_url"

    if ! curl -L -f -o "$temp_file" "$download_url"; then
        log_error "Failed to download release from: $download_url"
        rm -f "$temp_file"
        exit 1
    fi

    local binary_path="${INSTALL_DIR}/${BINARY_NAME}"

    if [[ "$UPDATE_MODE" == true ]] && [[ -f "$binary_path" ]]; then
        rm -f "$binary_path"
    fi

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

    local found_binary=""

    for name in "netwatcher-agent" "netwatcher" "agent"; do
        local candidate=$(find "$INSTALL_DIR" -maxdepth 1 -name "$name" -type f 2>/dev/null | grep -v '\.backup' | head -1)
        if [[ -n "$candidate" ]]; then
            found_binary="$candidate"
            break
        fi
    done

    if [[ -z "$found_binary" ]]; then
        found_binary=$(find "$INSTALL_DIR" -maxdepth 1 -type f -name "*netwatcher*" 2>/dev/null | grep -v '\.backup' | grep -v '\.conf$' | grep -v '\.json$' | grep -v '\.log' | head -1)
    fi

    if [[ -n "$found_binary" ]] && [[ "$found_binary" != "$binary_path" ]]; then
        mv "$found_binary" "$binary_path"
        found_binary="$binary_path"
    fi

    if [[ -n "$found_binary" ]]; then
        chmod +x "$found_binary"
    fi

    rm -f "$temp_file"

    if [[ ! -f "$binary_path" ]]; then
        log_error "Binary not found after installation: $binary_path"
        ls -la "$INSTALL_DIR" >&2
        exit 1
    fi

    log_success "NetWatcher Agent installed to: $binary_path"
}

create_config() {
    local config_path="${INSTALL_DIR}/${CONFIG_FILE}"

    log_info "Creating configuration file: $config_path"

    cat > "$config_path" << EOF
CONTROLLER_HOST=$CONTROLLER_HOST
CONTROLLER_SSL=$CONTROLLER_SSL
WORKSPACE_ID=$WORKSPACE_ID
AGENT_ID=$AGENT_ID
AGENT_PIN=$AGENT_PIN
EOF

    chmod 600 "$config_path"
    log_success "Configuration file created"
}

get_plist_destination() {
    if [[ "$BOOT_SERVICE" == true ]] || [[ "$SYSTEM_LEVEL" == true ]]; then
        echo "/Library/LaunchDaemons/${LAUNCHD_PLIST}"
    else
        echo "$HOME/Library/LaunchAgents/${LAUNCHD_PLIST}"
    fi
}

create_launchd_service() {
    if [[ "$NO_SERVICE" == true ]]; then
        log_info "Skipping launchd service creation"
        return
    fi

    local plist_path=$(get_plist_destination)
    local label="${SERVICE_NAME}"

    log_info "Creating launchd service file: $plist_path"

    if [[ "$BOOT_SERVICE" == true ]]; then
        cat > "$plist_path" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>--config</string>
        <string>${INSTALL_DIR}/${CONFIG_FILE}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/agent.log</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>UserName</key>
    <string>root</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF
    elif [[ "$SYSTEM_LEVEL" == true ]]; then
        cat > "$plist_path" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>--config</string>
        <string>${INSTALL_DIR}/${CONFIG_FILE}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/agent.log</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
EOF
    else
        cat > "$plist_path" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>--config</string>
        <string>${INSTALL_DIR}/${CONFIG_FILE}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/agent.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
EOF
    fi

    if [[ "$SYSTEM_LEVEL" == true ]]; then
        log_info "Loading system-level launchd service..."
        launchctl load -w "$plist_path"
    else
        log_info "Loading user-level launchd service..."
        launchctl load "$plist_path"
    fi

    log_success "Launchd service created and loaded"
}

start_service() {
    if [[ "$NO_SERVICE" == true ]] || [[ "$NO_START" == true ]]; then
        log_info "Skipping service startup"
        return
    fi

    local plist_path=$(get_plist_destination)
    local label="${SERVICE_NAME}"

    log_info "Starting NetWatcher Agent service..."

    if [[ "$SYSTEM_LEVEL" == true ]]; then
        launchctl start "$label"
    else
        launchctl start "$label"
    fi

    sleep 2

    if launchctl list | grep -q "${label}"; then
        local pid=$(launchctl list | grep "${label}" | awk '{print $1}')
        if [[ -n "$pid" ]] && [[ "$pid" != "-" ]]; then
            log_success "Service is running (PID: $pid)"
            return
        fi
    fi

    log_warning "Service may have failed to start. Check logs at: ${INSTALL_DIR}/agent.log"
}

check_existing_installation() {
    if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]] && [[ "$FORCE_INSTALL" != true ]]; then
        log_warning "NetWatcher Agent is already installed at $INSTALL_DIR"
        log_info "Use --force to reinstall"

        local label="${SERVICE_NAME}"
        if launchctl list | grep -q "${label}"; then
            log_info "Service is currently loaded"
        fi

        exit 0
    fi
}

stop_existing_service() {
    local label="${SERVICE_NAME}"

    if launchctl list | grep -q "${label}"; then
        log_info "Stopping existing NetWatcher Agent service..."
        launchctl stop "$label" 2>/dev/null || true
        sleep 1
    fi
}

install_dependencies() {
    log_info "Checking dependencies..."

    local deps=("curl")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" > /dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Installing missing dependencies: ${missing[*]}"
        if command -v brew > /dev/null 2>&1; then
            brew install "${missing[@]}"
        else
            log_error "Could not install dependencies. Please install manually: ${missing[*]}"
            exit 1
        fi
    fi
}

show_summary() {
    log_success "NetWatcher Agent installation completed!"
    echo
    log_info "Installation Details:"
    echo "  - Binary: ${INSTALL_DIR}/${BINARY_NAME}"
    echo "  - Config: ${INSTALL_DIR}/${CONFIG_FILE}"
    echo "  - Service: $SERVICE_NAME"
    echo "  - Service level: $([[ "$BOOT_SERVICE" == true ]] && echo "boot service (hidden)" || ([[ "$SYSTEM_LEVEL" == true ]] && echo "system-wide" || echo "user-level"))"
    echo "  - Version: $VERSION"
    echo
    log_info "Useful Commands:"
    echo "  - Check status: launchctl list | grep ${SERVICE_NAME}"
    echo "  - View logs: tail -f ${INSTALL_DIR}/agent.log"
    echo "  - Restart: launchctl stop ${SERVICE_NAME} && launchctl start ${SERVICE_NAME}"
    echo "  - Stop: launchctl stop ${SERVICE_NAME}"
    echo "  - Unload: launchctl unload $(get_plist_destination)"
    echo
    if [[ "$NO_SERVICE" != true ]]; then
        if [[ "$BOOT_SERVICE" == true ]]; then
            log_info "The NetWatcher Agent is now running as a boot service and will start automatically at system boot (hidden from Dock)."
        elif [[ "$SYSTEM_LEVEL" == true ]]; then
            log_info "The NetWatcher Agent is now running as a system service and will start automatically on boot."
        else
            log_info "The NetWatcher Agent is now running as a user service and will start automatically on login."
        fi
    fi
}

uninstall_agent() {
    echo "NetWatcher Agent Uninstallation"
    echo "================================"
    echo

    local has_service=false
    local has_files=false
    local label="${SERVICE_NAME}"
    local plist_path=$(get_plist_destination)

    if launchctl list | grep -q "${label}"; then
        has_service=true
    fi

    if [[ -d "$INSTALL_DIR" ]]; then
        has_files=true
    fi

    if [[ "$has_service" == false ]] && [[ "$has_files" == false ]]; then
        log_warning "NetWatcher Agent does not appear to be installed"
        return 0
    fi

    if [[ "$FORCE_INSTALL" != true ]]; then
        log_warning "This will completely remove NetWatcher Agent from your system."
        echo "The following will be removed:"
        if [[ "$has_service" == true ]]; then
            echo "  - Launchd service: $label"
            echo "  - Plist: $plist_path"
        fi
        if [[ "$has_files" == true ]]; then
            echo "  - Installation directory: $INSTALL_DIR"
        fi
        echo

        read -p "Are you sure you want to continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Uninstallation cancelled"
            return 0
        fi
    fi

    if [[ "$has_service" == true ]]; then
        log_info "Stopping $label service..."
        launchctl stop "$label" 2>/dev/null || true

        log_info "Unloading launchd service..."
        launchctl unload "$plist_path" 2>/dev/null || true

        log_info "Removing plist file..."
        rm -f "$plist_path"

        log_success "Launchd service removed"
    fi

    if [[ "$has_files" == true ]]; then
        log_info "Removing installation directory: $INSTALL_DIR"
        rm -rf "$INSTALL_DIR"
        log_success "Installation directory removed"
    fi

    echo
    log_success "NetWatcher Agent has been uninstalled"
}

update_agent() {
    echo "NetWatcher Agent Binary Update"
    echo "==============================="
    echo

    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "NetWatcher Agent is not installed at $INSTALL_DIR"
        log_info "Use the full installation command to install first."
        exit 1
    fi

    if [[ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        log_error "Binary not found at ${INSTALL_DIR}/${BINARY_NAME}"
        log_info "Use the full installation command to install first."
        exit 1
    fi

    local current_version=""
    if [[ -x "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        current_version=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | grep -oE 'v[0-9]{8}-[a-f0-9]+' | head -1)
        if [[ -z "$current_version" ]]; then
            current_version=$(strings "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null | grep -oE 'v[0-9]{8}-[a-f0-9]+' | head -1 || echo "unknown")
        fi
        log_info "Current version: $current_version"
    fi

    detect_architecture
    get_latest_version

    log_info "Updating to version: $VERSION"

    local label="${SERVICE_NAME}"
    if launchctl list | grep -q "${label}"; then
        log_info "Stopping $label service..."
        launchctl stop "$label"
    fi

    local backup_path="${INSTALL_DIR}/${BINARY_NAME}.backup"
    log_info "Backing up current binary to: $backup_path"
    cp "${INSTALL_DIR}/${BINARY_NAME}" "$backup_path"

    download_and_install

    if [[ -x "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
        local new_version=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | grep -oE 'v[0-9]{8}-[a-f0-9]+' | head -1)
        if [[ -z "$new_version" ]]; then
            new_version=$(strings "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null | grep -oE 'v[0-9]{8}-[a-f0-9]+' | head -1 || echo "unknown")
        fi
        log_success "New version installed: $new_version"

        rm -f "$backup_path"
    else
        log_error "New binary is not executable. Rolling back..."
        mv "$backup_path" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
        exit 1
    fi

    if launchctl list | grep -q "${label}" && [[ "$NO_SERVICE" != true ]]; then
        log_info "Starting $label service..."
        launchctl start "$label"
        sleep 2
        if launchctl list | grep -q "${label}"; then
            log_success "Service restarted successfully"
        else
            log_warning "Service may have failed to start. Check logs at: ${INSTALL_DIR}/agent.log"
        fi
    fi

    echo
    log_success "NetWatcher Agent binary updated successfully!"
    echo "  Old version: $current_version"
    echo "  New version: $new_version"
}

main() {
    echo "NetWatcher Agent macOS Installation Script"
    echo "=========================================="
    echo

    parse_arguments "$@"

    if [[ "$UNINSTALL_MODE" == true ]]; then
        uninstall_agent
        return
    fi

    if [[ "$UPDATE_MODE" == true ]]; then
        install_dependencies
        update_agent
        return
    fi

    validate_arguments
    detect_architecture
    install_dependencies
    check_existing_installation
    stop_existing_service
    get_latest_version
    download_and_install

    local auth_file="${INSTALL_DIR}/agent_auth.json"
    if [[ -f "$auth_file" ]]; then
        log_info "Removing stale auth file to force re-authentication..."
        rm -f "$auth_file"
    fi

    local deactivated_file="${INSTALL_DIR}/DEACTIVATED"
    if [[ -f "$deactivated_file" ]]; then
        log_info "Removing DEACTIVATED marker from previous installation..."
        rm -f "$deactivated_file"
    fi

    create_config
    create_launchd_service
    start_service
    show_summary
}

main "$@"
