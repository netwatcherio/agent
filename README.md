# NetWatcher Agent

A lightweight network monitoring agent that reports metrics to the NetWatcher platform.

## Features

- **MTR Checks** - Traceroute analysis using Trippy
- **Ping Tests** - ICMP latency monitoring with pro-bing
- **Traffic Simulation** - Synthetic traffic using rPerf
- **System Information** - Host metrics and status
- **Network Information** - Interface and connectivity data
- **Speedtests** - Bandwidth testing (coming soon)
- **Auto-Updates** - Automatic version updates from GitHub releases

## Requirements

- **Platforms**: Linux, macOS, Windows
- **Permissions**: Root/Administrator (required for ICMP and raw sockets)
- **NetWatcher Controller**: Running instance of [netwatcher-oss](https://github.com/netwatcherio/oss)

## Quick Start

### Linux / macOS

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

### Self-Hosted Deployment

For self-hosted NetWatcher instances:

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/master/install.sh | sudo bash -s -- \
  --host your-controller.example.com \
  --ssl true \
  --workspace 1 \
  --id 42 \
  --pin 123456789
```

```powershell
# Windows
.\install.ps1 -Host "your-controller.example.com" -SSL $true -Workspace 1 -Id 42 -Pin "123456789"
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
| Linux/macOS | `/opt/netwatcher-agent/config.conf` |
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

## Uninstallation

```bash
# Linux/macOS
sudo ./install.sh --uninstall

# Windows
.\install.ps1 -Uninstall
```

## Troubleshooting

### Failed Auto-Updates

If the agent's auto-update fails (e.g., read-only `/tmp`, network issues), use the install script to manually update:

```bash
# Linux/macOS - Update binary only (preserves config/service)
sudo ./install.sh --update

# Update to a specific version
sudo ./install.sh --update --version v20260114-abc123

# Windows
.\install.ps1 -Update
.\install.ps1 -Update -Version "v20260114-abc123"
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

- [trippy](https://github.com/fujiapple852/trippy) - MTR/traceroute
- [pro-bing](https://github.com/prometheus-community/pro-bing) - ICMP ping
- [rperf](https://github.com/opensource-3d-p/rperf) - Traffic simulation

## License

[GNU Affero General Public License v3.0](LICENSE.md)
