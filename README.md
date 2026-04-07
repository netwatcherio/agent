# NetWatcher Agent

A lightweight network monitoring agent that reports metrics to the NetWatcher platform.

## Features

- **MTR Checks** - Traceroute analysis using Trippy
- **Ping Tests** - ICMP latency monitoring with pro-bing
- **DNS Monitoring** - DNS resolution time and record validation
- **Traffic Simulation** - Synthetic UDP traffic between agents
- **System Information** - Host metrics and status
- **Network Information** - Interface and connectivity data
- **Speedtests** - On-demand bandwidth testing
- **Auto-Updates** - Automatic version updates from GitHub releases

## Requirements

- **Platforms**: Linux, macOS, Windows
- **Permissions**: Root/Administrator (required for ICMP and raw sockets)
- **NetWatcher Controller**: Running instance of [netwatcher-oss](https://github.com/netwatcherio/oss)

## Quick Start

### Linux

```bash
# Download and run the installer
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/master/install.sh | sudo bash -s -- \
  --workspace YOUR_WORKSPACE_ID \
  --id YOUR_AGENT_ID \
  --pin YOUR_AGENT_PIN
```

### Windows (PowerShell as Administrator)

```powershell
# Download the installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/netwatcherio/agent/master/install.ps1" -OutFile "install.ps1"

# Run the installer
.\install.ps1 -Workspace YOUR_WORKSPACE_ID -Id YOUR_AGENT_ID -Pin "YOUR_AGENT_PIN"
```

> **Note:** If you encounter an execution policy error, run PowerShell as Administrator and use:
> ```powershell
> powershell -ExecutionPolicy Bypass -File install.ps1 -Workspace YOUR_WORKSPACE_ID -Id YOUR_AGENT_ID -Pin "YOUR_AGENT_PIN"
> ```

### macOS

```bash
# Download and run the installer (user-level, no sudo)
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/master/install-macos.sh | bash -s -- \
  --workspace YOUR_WORKSPACE_ID \
  --id YOUR_AGENT_ID \
  --pin YOUR_AGENT_PIN

# Or system-level (requires sudo, runs at boot)
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/master/install-macos.sh | sudo bash -s -- \
  --workspace YOUR_WORKSPACE_ID \
  --id YOUR_AGENT_ID \
  --pin YOUR_AGENT_PIN \
  --system
```

For detailed macOS installation and administration documentation, see [docs/agent-installation-macos.md](../docs/agent-installation-macos.md).

### Self-Hosted Deployment

For self-hosted NetWatcher instances:

```bash
# Linux
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/master/install.sh | sudo bash -s -- \
  --host your-controller.example.com \
  --ssl true \
  --workspace 1 \
  --id 42 \
  --pin 123456789
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File install.ps1 -Host "your-controller.example.com" -SSL $true -Workspace 1 -Id 42 -Pin "123456789"
```

## Configuration

The agent stores its configuration in `config.conf`:

| Parameter | Description |
|-----------|-------------|
| `CONTROLLER_HOST` | Controller hostname (e.g., `api.netwatcher.io`) |
| `CONTROLLER_SSL` | Use HTTPS/WSS (`true` or `false`) |
| `WORKSPACE_ID` | Workspace ID |
| `AGENT_ID` | Agent ID |
| `AGENT_PIN` | Initial authentication PIN |

### Configuration Locations

| Platform | Path |
|----------|------|
| Linux | `/opt/netwatcher-agent/config.conf` |
| macOS (user-level) | `~/netwatcher-agent/config.conf` |
| macOS (system-level) | `/var/root/netwatcher-agent/config.conf` |
| Windows | `C:\Program Files\NetWatcher-Agent\config.conf` |

## Service Management

### Linux (systemd)

```bash
sudo systemctl status netwatcher-agent   # Check status
sudo systemctl restart netwatcher-agent  # Restart
sudo journalctl -u netwatcher-agent -f   # View logs
```

### Windows

```powershell
Get-Service -Name NetWatcherAgent        # Check status
Restart-Service -Name NetWatcherAgent    # Restart
Get-EventLog -LogName Application -Source NetWatcherAgent -Newest 20  # View logs
```

### macOS (launchd)

```bash
# User-level service
launchctl list | grep com.netwatcher.agent   # Check status
tail -f ~/netwatcher-agent/agent.log          # View logs
launchctl stop com.netwatcher.agent && launchctl start com.netwatcher.agent  # Restart

# System-level service
sudo launchctl list | grep com.netwatcher.agent   # Check status
sudo tail -f /var/root/netwatcher-agent/agent.log # View logs
```

## Installer Options

### Linux (`install.sh`)

| Flag | Description |
|------|-------------|
| `--workspace`, `-w` | Workspace ID (required for install) |
| `--id`, `-i` | Agent ID (required for install) |
| `--pin`, `-p` | Agent PIN (required for install) |
| `--host` | Controller host (default: `api.netwatcher.io`) |
| `--ssl` | Use SSL/HTTPS — `true` or `false` (default: `true`) |
| `--install-dir` | Installation directory (default: `/opt/netwatcher-agent`) |
| `--version` | Install a specific version tag |
| `--force` | Force reinstallation or skip uninstall confirmation |
| `--no-service` | Skip systemd service creation |
| `--no-start` | Don't start the service after installation |
| `--update` | Update only the binary (preserves config and service) |
| `--uninstall` | Uninstall the agent |
| `--debug` | Enable debug output |

```bash
# Update to latest
sudo ./install.sh --update

# Update to specific version
sudo ./install.sh --update --version v20260219-5c692b8

# Uninstall
sudo ./install.sh --uninstall

# Force uninstall without confirmation
sudo ./install.sh --uninstall --force
```

### macOS (`install-macos.sh`)

| Flag | Description |
|------|-------------|
| `--workspace`, `-w` | Workspace ID (required for install) |
| `--id`, `-i` | Agent ID (required for install) |
| `--pin`, `-p` | Agent PIN (required for install) |
| `--host` | Controller host (default: `api.netwatcher.io`) |
| `--ssl` | Use SSL/HTTPS — `true` or `false` (default: `true`) |
| `--install-dir` | Installation directory (default: `~/netwatcher-agent`) |
| `--system` | Install as system-level service (requires sudo) |
| `--user` | Install as user-level service (default, no sudo) |
| `--force` | Force reinstallation or skip uninstall confirmation |
| `--no-service` | Skip launchd service creation |
| `--no-start` | Don't start the service after installation |
| `--version` | Install a specific version tag |
| `--update` | Update only the binary (preserves config and service) |
| `--uninstall` | Uninstall the agent |
| `--debug` | Enable debug output |

```bash
# Update to latest
./install-macos.sh --update

# Update to specific version
./install-macos.sh --update --version v20260219-5c692b8

# Uninstall
./install-macos.sh --uninstall

# Force uninstall without confirmation
./install-macos.sh --uninstall --force
```

### Windows (`install.ps1`)

| Flag | Description |
|------|-------------|
| `-Workspace` | Workspace ID (required for install) |
| `-Id` | Agent ID (required for install) |
| `-Pin` | Agent PIN (required for install) |
| `-ControllerHost` | Controller host (default: `api.netwatcher.io`) |
| `-SSL` | Use SSL/HTTPS (default: `$true`) |
| `-InstallDir` | Installation directory (default: `C:\Program Files\NetWatcher-Agent`) |
| `-Version` | Install a specific version tag |
| `-Force` | Force reinstallation |
| `-NoStart` | Don't start the service after installation |
| `-Update` | Update only the binary (preserves config and service) |
| `-UpdateVersion` | Specific version to update to (used with `-Update`) |
| `-Uninstall` | Uninstall the agent |

```powershell
# Update to latest
.\install.ps1 -Update

# Update to specific version
.\install.ps1 -Update -UpdateVersion "v20260219-5c692b8"

# Uninstall
.\install.ps1 -Uninstall

# Force uninstall without confirmation
.\install.ps1 -Uninstall -Force
```

## Troubleshooting

### Failed Auto-Updates

If the agent's auto-update fails (e.g., read-only `/tmp`, network issues), use the install script to manually update. See [Installer Options](#installer-options) above for all flags.

```bash
# Linux
sudo ./install.sh --update

# Windows
.\install.ps1 -Update
```

### Manual Binary Replacement

If the install script isn't available, manually replace the binary:

```bash
# 1. Stop the service
sudo systemctl stop netwatcher-agent

# 2. Download the latest release
# Visit: https://github.com/netwatcherio/agent/releases/latest
# Download the appropriate file for your platform (e.g., linux-amd64.zip)

# 3. Extract and replace
cd /opt/netwatcher-agent
unzip ~/Downloads/netwatcher-*.zip -d /tmp/nw-update
cp /tmp/nw-update/netwatcher-agent ./netwatcher-agent
chmod +x ./netwatcher-agent

# 4. Verify and restart
./netwatcher-agent --version
sudo systemctl start netwatcher-agent
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Auto-update fails with "read-only file system" | Updated agents create `.tmp` folder locally instead of using `/tmp`. Update manually with `--update` flag. |
| Service fails to start after update | Check logs: `journalctl -u netwatcher-agent -n 50`. Rollback if needed by restoring `.backup` file. |
| Agent not connecting to controller | Verify `config.conf` settings, check firewall, ensure controller is reachable. |
| "Unauthorized" errors | Re-bootstrap with correct PIN or generate new agent credentials in the dashboard. |

### Viewing Logs

```bash
# Linux - Follow logs live
sudo journalctl -u netwatcher-agent -f

# Linux - Last 100 lines
sudo journalctl -u netwatcher-agent -n 100

# macOS - User-level
tail -f ~/netwatcher-agent/agent.log

# macOS - System-level
sudo tail -f /var/root/netwatcher-agent/agent.log

# Windows
Get-EventLog -LogName Application -Source NetWatcherAgent -Newest 50
```

## Building from Source

```bash
git clone https://github.com/netwatcherio/agent
cd agent
go build -o netwatcher-agent
```

## Libraries


- [pro-bing](https://github.com/prometheus-community/pro-bing) - ICMP ping
- [rperf](https://github.com/opensource-3d-p/rperf) - Traffic simulation

## License

[GNU Affero General Public License v3.0](LICENSE.md)
