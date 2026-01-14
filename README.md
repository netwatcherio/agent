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
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/main/install.sh | sudo bash -s -- \
  --workspace YOUR_WORKSPACE_ID \
  --id YOUR_AGENT_ID \
  --pin YOUR_AGENT_PIN
```

### Windows (PowerShell as Administrator)

```powershell
# Download the installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/netwatcherio/agent/main/install.ps1" -OutFile "install.ps1"

# Run the installer
.\install.ps1 -Workspace YOUR_WORKSPACE_ID -Id YOUR_AGENT_ID -Pin "YOUR_AGENT_PIN"
```

### Self-Hosted Deployment

For self-hosted NetWatcher instances:

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/netwatcherio/agent/main/install.sh | sudo bash -s -- \
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
