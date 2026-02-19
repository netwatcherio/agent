package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/iris/v12/websocket"
	"github.com/netwatcherio/netwatcher-agent/probes"

	"github.com/kataras/neffos"
	"github.com/kataras/neffos/gobwas"
	log "github.com/sirupsen/logrus"
)

// ErrAgentDeleted is returned when the controller returns 410 Gone,
// indicating this agent has been permanently deleted from the workspace.
var ErrAgentDeleted = errors.New("agent has been deleted from controller")

/*
ENV VARS:

  CONTROLLER_HOST          e.g. localhost:8080 or api.example.com (host:port, no protocol)
  CONTROLLER_SSL           true/false - use HTTPS/WSS (default: false)
  WORKSPACE_ID             uint
  AGENT_ID                 uint
  AGENT_PIN                optional (used if PSK missing for initial bootstrap)
  AGENT_PSK                optional (preferred, saved after bootstrap)

Behavior:
  - Try PSK first; otherwise bootstrap via PIN.
  - Persist the server's EXACT login JSON to agent_auth.json (next to the executable).
  - Connect WS (gobwas) with headers: X-Workspace-ID, X-Agent-ID, X-Agent-PSK.
  - Reconnects automatically on drop.
*/

const (
	namespace             = "agent"
	dialAndConnectTimeout = 5 * time.Second
	AuthFileName          = "agent_auth.json"
)

type Agent struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
	UpdatedAt time.Time `gorm:"index" json:"updated_at"`

	// Ownership / scoping
	WorkspaceID uint `gorm:"index:idx_ws_pin,priority:1" json:"workspace_id"`

	// Identity
	Name        string `gorm:"size:255;index" json:"name" form:"name"`
	Description string `gorm:"size:255;index" json:"description" form:"description"`

	// Network
	Location         string `gorm:"size:255" json:"location"`
	PublicIPOverride string `gorm:"size:64" json:"public_ip_override"`

	// Runtime / versioning
	Version string `gorm:"size:64;index" json:"version"`

	// Health
	LastSeenAt time.Time `gorm:"index" json:"last_seen_at"`

	Initialized bool `gorm:"default:false" json:"initialized"`

	// Authentication (post-bootstrap)
	PSKHash string `gorm:"size:255" json:"-"` // bcrypt hash of server-generated PSK
}

type LoginResponse struct {
	Status string `json:"status"`          // "ok" | "bootstrapped" | "deleted"
	PSK    string `json:"psk,omitempty"`   // only on bootstrap
	Agent  Agent  `json:"agent,omitempty"` // convenience
	Error  string `json:"error,omitempty"` // on failure
}

// --- API payloads (minimal; we keep raw for persistence) ---

type agentLoginRequest struct {
	WorkspaceID uint   `json:"workspace_id,omitempty"`
	AgentID     uint   `json:"agent_id,omitempty"`
	PSK         string `json:"psk,omitempty"`
	PIN         string `json:"pin,omitempty"`
}

type agentLoginResponse struct {
	Status string `json:"status"`
	PSK    string `json:"psk,omitempty"`
	Error  string `json:"error,omitempty"`

	_raw []byte // raw body to persist exactly
}

// --- Config ---

type Config struct {
	ControllerHost string // Host:port without protocol (e.g., "localhost:8080" or "api.example.com")
	SSL            bool   // Use HTTPS/WSS instead of HTTP/WS
	APIURL         string // Derived: http(s)://ControllerHost/agent
	WSURL          string // Derived: ws(s)://ControllerHost/ws/agent
	WorkspaceID    uint
	AgentID        uint
	PIN            string
	PSK            string
}

func mustEnv(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

func parseUintEnv(name string) uint {
	s := mustEnv(name)
	u64, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		log.Fatalf("invalid %s: %v", name, err)
	}
	return uint(u64)
}

func parseBoolEnv(name string, defaultVal bool) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return defaultVal
	}
	v = strings.ToLower(v)
	return v == "true" || v == "1" || v == "yes"
}

// LoadConfigFromEnv loads configuration from environment variables.
// Uses CONTROLLER_HOST as the base host:port and derives API/WS URLs automatically.
// Set CONTROLLER_SSL=true to use HTTPS/WSS instead of HTTP/WS.
func LoadConfigFromEnv() Config {
	controllerHost := mustEnv("CONTROLLER_HOST")

	// Strip any protocol prefix if provided (normalize to just host:port)
	controllerHost = strings.TrimPrefix(controllerHost, "https://")
	controllerHost = strings.TrimPrefix(controllerHost, "http://")
	controllerHost = strings.TrimPrefix(controllerHost, "wss://")
	controllerHost = strings.TrimPrefix(controllerHost, "ws://")
	controllerHost = strings.TrimSuffix(controllerHost, "/")

	// Determine SSL from CONTROLLER_SSL env var (defaults to false)
	ssl := parseBoolEnv("CONTROLLER_SSL", false)

	// Build protocol prefixes
	httpProto := "http://"
	wsProto := "ws://"
	if ssl {
		httpProto = "https://"
		wsProto = "wss://"
	}

	return Config{
		ControllerHost: controllerHost,
		SSL:            ssl,
		APIURL:         httpProto + controllerHost + "/agent",
		WSURL:          wsProto + controllerHost + "/ws/agent",
		WorkspaceID:    parseUintEnv("WORKSPACE_ID"),
		AgentID:        parseUintEnv("AGENT_ID"),
		PIN:            strings.TrimSpace(os.Getenv("AGENT_PIN")),
		PSK:            strings.TrimSpace(os.Getenv("AGENT_PSK")),
	}
}

// --- Login ---

func DoLogin(ctx context.Context, cfg Config) (*LoginResponse, error) {
	req := agentLoginRequest{
		WorkspaceID: cfg.WorkspaceID,
		AgentID:     cfg.AgentID,
	}
	if cfg.PSK != "" {
		req.PSK = cfg.PSK
	} else if cfg.PIN != "" {
		req.PIN = cfg.PIN
	} else {
		return nil, errors.New("either AGENT_PSK or AGENT_PIN must be provided")
	}

	b, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIURL, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	var out LoginResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("login decode: %w\n%s", err, raw)
	}

	// 410 Gone means the agent was deleted from the controller.
	// Remove local auth and return a specific error so the caller can self-uninstall.
	if resp.StatusCode == http.StatusGone {
		log.Warnf("Controller returned 410 Gone — agent has been deleted (status=%s)", out.Status)
		RemoveAuthFile()
		return &out, ErrAgentDeleted
	}

	if resp.StatusCode != http.StatusOK {
		if out.Error == "" {
			out.Error = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		return &out, fmt.Errorf("login failed: %s", out.Error)
	}

	return &out, nil
}

func SaveRawAuthJSON(raw []byte) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	outPath := filepath.Join(dir, AuthFileName)
	return os.WriteFile(outPath, raw, 0600)
}

// --- WebSocket client (neffos + gobwas) ---

type WSClient struct {
	URL              string
	WorkspaceID      uint
	AgentID          uint
	PSK              string
	ProbeGetCh       chan []probes.Probe
	SpeedtestQueueCh chan []probes.SpeedtestQueueItem
	WsConn           *neffos.NSConn
	AgentVersion     string
	// Failure tracking for auto-reconnect
	probeGetFailures    int
	maxProbeGetFailures int // Max consecutive failures before reconnect (default 5)
	reconnectInProgress bool

	// Deactivation state — set when controller signals agent deletion.
	// Once true, the agent will stop reconnecting and attempt self-uninstall.
	Deactivated  bool
	DeactivateCh chan string        // receives the deactivation reason; buffered(1)
	CancelFunc   context.CancelFunc // cancel function for the parent context
}

func (c *WSClient) namespaces() neffos.Namespaces {
	return neffos.Namespaces{
		namespace: neffos.Events{
			neffos.OnNamespaceConnected: func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: connected to namespace [%s]", msg.Namespace)
				// Ask server for probes; your server replies with "bing bong" currently.
				if ok := ns.Emit("probe_get", []byte("hello")); !ok {
					log.Warn("WS: emit probe_get returned false")
				}

				// update version on connect/reconnect
				var versionData = struct {
					Version string `json:"version"`
				}{}

				versionData.Version = c.AgentVersion
				vM, _ := json.Marshal(versionData)

				if ok := ns.Emit("version", vM); !ok {
					log.Warn("WS: emit version returned not ok")
				}

				// Fetch and send speedtest servers on connect
				go func() {
					servers, err := probes.FetchSpeedtestServers()
					if err != nil {
						log.Errorf("WS: failed to fetch speedtest servers: %v", err)
						return
					}
					data, _ := json.Marshal(servers)
					if ok := ns.Emit("speedtest_servers", data); !ok {
						log.Warn("WS: emit speedtest_servers returned false")
					}
					log.Infof("WS: sent %d speedtest servers to controller", len(servers))
				}()

				return nil
			},
			neffos.OnNamespaceDisconnect: func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: disconnected from namespace [%s]", msg.Namespace)
				// Do NOT reconnect if the agent has been deactivated
				if c.Deactivated {
					log.Warn("WS: agent is deactivated, NOT reconnecting")
					return nil
				}
				// Use CancelFunc-aware context if available, otherwise background
				go c.ConnectWithRetry(context.Background())
				return nil
			},

			// ---- Deactivation handler ----
			// Sent by the controller when an admin deletes this agent from the panel.
			// The agent should clean up, remove credentials, and attempt self-uninstall.
			"deactivate": func(ns *neffos.NSConn, msg neffos.Message) error {
				var deactivateMsg struct {
					Reason string `json:"reason"`
				}
				reason := "unknown"
				if err := json.Unmarshal(msg.Body, &deactivateMsg); err == nil && deactivateMsg.Reason != "" {
					reason = deactivateMsg.Reason
				}

				log.Warnf("===========================================================")
				log.Warnf("AGENT DEACTIVATED by controller (reason: %s)", reason)
				log.Warnf("===========================================================")

				// Mark as deactivated to prevent reconnection
				c.Deactivated = true

				// Remove saved credentials so agent cannot authenticate on restart
				RemoveAuthFile()

				// Signal the deactivation channel so main.go can react
				if c.DeactivateCh != nil {
					select {
					case c.DeactivateCh <- reason:
					default:
						// Channel full or nobody listening; proceed with shutdown anyway
					}
				}

				// Cancel the parent context to trigger graceful shutdown
				if c.CancelFunc != nil {
					c.CancelFunc()
				}

				return nil
			},

			"probe_get": func(ns *neffos.NSConn, msg neffos.Message) error {
				var p []probes.Probe

				// Set default max failures if not configured
				if c.maxProbeGetFailures == 0 {
					c.maxProbeGetFailures = 5
				}

				// Handle empty or malformed messages gracefully (common during reconnection)
				if len(msg.Body) == 0 {
					c.probeGetFailures++
					log.Debugf("WS: probe_get received empty body (%d/%d failures)", c.probeGetFailures, c.maxProbeGetFailures)

					// Trigger reconnect if too many consecutive failures
					if c.probeGetFailures >= c.maxProbeGetFailures && !c.reconnectInProgress {
						log.Warnf("WS: too many probe_get failures (%d), triggering reconnection", c.probeGetFailures)
						c.probeGetFailures = 0
						c.reconnectInProgress = true
						go func() {
							time.Sleep(2 * time.Second) // Brief pause before reconnecting
							c.reconnectInProgress = false
							if !c.Deactivated {
								c.ConnectWithRetry(context.Background())
							}
						}()
					}
					return nil
				}

				if err := json.Unmarshal(msg.Body, &p); err != nil {
					c.probeGetFailures++
					log.Debugf("WS: probe_get unmarshal error (%d/%d failures): %v", c.probeGetFailures, c.maxProbeGetFailures, err)

					// Trigger reconnect if too many consecutive failures
					if c.probeGetFailures >= c.maxProbeGetFailures && !c.reconnectInProgress {
						log.Warnf("WS: too many probe_get failures (%d), triggering reconnection", c.probeGetFailures)
						c.probeGetFailures = 0
						c.reconnectInProgress = true
						go func() {
							time.Sleep(2 * time.Second)
							c.reconnectInProgress = false
							if !c.Deactivated {
								c.ConnectWithRetry(context.Background())
							}
						}()
					}
					return nil
				}

				// Success! Reset failure counter
				c.probeGetFailures = 0

				if len(p) > 0 {
					// Log summary instead of full JSON
					typeCounts := make(map[string]int)
					for _, probe := range p {
						typeCounts[string(probe.Type)]++
					}
					log.Infof("WS: received %d probes: %v", len(p), typeCounts)
					c.ProbeGetCh <- p
				} else {
					log.Debugf("WS: received empty probe list")
				}

				return nil
			},
			"speedtest_servers_ok": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Debugf("WS: speedtest_servers acknowledged")
				return nil
			},
			"speedtest_queue": func(ns *neffos.NSConn, msg neffos.Message) error {
				var items []probes.SpeedtestQueueItem
				if err := json.Unmarshal(msg.Body, &items); err != nil {
					log.Errorf("WS: failed to unmarshal speedtest_queue: %v", err)
					return err
				}
				log.Infof("WS: received %d speedtest queue items", len(items))
				if c.SpeedtestQueueCh != nil {
					c.SpeedtestQueueCh <- items
				}
				return nil
			},
			"speedtest_result_ok": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Debugf("WS: speedtest_result acknowledged")
				return nil
			},
		},
	}
}

func (c *WSClient) dialOnce(ctx context.Context) (*neffos.Client, error) {
	// Headers exactly as your backend expects
	headers := websocket.GobwasHeader{
		"X-Workspace-ID": []string{fmt.Sprintf("%d", c.WorkspaceID)},
		"X-Agent-ID":     []string{fmt.Sprintf("%d", c.AgentID)},
		"X-Agent-PSK":    []string{c.PSK},
	}

	// gobwas adapter for neffos
	dialer := gobwas.Dialer(gobwas.Options{
		Header: headers,
	})

	return neffos.Dial(ctx, dialer, c.URL, c.namespaces())
}

func (c *WSClient) ConnectWithRetry(parent context.Context) {
	delay := 1 * time.Second
	maxDelay := 2 * time.Minute

	for {
		// Check deactivation flag before every attempt
		if c.Deactivated {
			log.Warn("WS: agent is deactivated, aborting reconnection")
			return
		}

		select {
		case <-parent.Done():
			return
		default:
		}

		// Dial
		ctx, cancel := context.WithTimeout(parent, dialAndConnectTimeout)
		client, err := c.dialOnce(ctx)
		cancel()
		if err != nil {
			// Check if the dial error indicates agent deletion (410 Gone).
			// The WebSocket upgrade failure from the server may contain this signal.
			errStr := err.Error()
			if strings.Contains(errStr, "410") || strings.Contains(errStr, "agent_deleted") {
				log.Warnf("WS: server rejected connection — agent has been deleted")
				c.Deactivated = true
				RemoveAuthFile()
				if c.DeactivateCh != nil {
					select {
					case c.DeactivateCh <- "deleted_on_reconnect":
					default:
					}
				}
				if c.CancelFunc != nil {
					c.CancelFunc()
				}
				return
			}

			log.Errorf("WS dial error: %v (retry in %s)", err, delay)
			time.Sleep(delay)
			if delay < maxDelay {
				delay *= 2
			}
			continue
		}

		// Join namespace
		ctx2, cancel2 := context.WithTimeout(parent, dialAndConnectTimeout)
		ns, err := client.Connect(ctx2, namespace)
		cancel2()
		if err != nil {
			log.Errorf("WS join namespace error: %v (retry in %s)", err, delay)
			client.Close()
			time.Sleep(delay)
			if delay < maxDelay {
				delay *= 2
			}
			continue
		}

		// Connected: hold until parent cancels
		c.WsConn = ns
		delay = 1 * time.Second // reset backoff

		<-parent.Done()

		client.Close()
		err = ns.Disconnect(ctx)
		if err != nil {
			return
		}
		return
	}
}

// --- main ---

/*func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.InfoLevel)

	cfg := loadConfigFromEnv()

	// 1) Login and persist exact JSON
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	loginResp, err := doLogin(ctx, cfg)
	cancel()
	if err != nil {
		log.Fatalf("login error: %v (server said: %s)", err, safeErr(loginResp))
	}
	if err := saveRawAuthJSON(loginResp._raw); err != nil {
		log.Fatalf("failed to save %s: %v", authFileName, err)
	}
	log.Infof("Saved %s (status=%s)", authFileName, loginResp.Status)

	// Decide PSK to use
	psk := cfg.PSK
	if loginResp.PSK != "" {
		psk = loginResp.PSK
	}
	if psk == "" {
		log.Fatalf("no PSK available after login; cannot open websocket")
	}

	// 2) WS client with gobwas + headers
	wsClient := &WSClient{
		URL:         cfg.WSURL,       // e.g. ws://host:8080/ws
		WorkspaceID: cfg.WorkspaceID, // header: X-Workspace-ID
		AgentID:     cfg.AgentID,     // header: X-Agent-ID
		PSK:         psk,             // header: X-Agent-PSK
	}

	// Handle Ctrl+C / SIGTERM
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go wsClient.connectWithRetry(parent)

	<-parent.Done()
	log.Info("shutting down")
}*/

func SafeErr(r *LoginResponse) string {
	if r == nil {
		return ""
	}
	return r.Error
}

// RemoveAuthFile deletes the saved agent_auth.json credential file.
// Called during deactivation to prevent the agent from re-authenticating after restart.
func RemoveAuthFile() {
	exe, err := os.Executable()
	if err != nil {
		log.Warnf("Cannot determine executable path for auth file removal: %v", err)
		return
	}
	authPath := filepath.Join(filepath.Dir(exe), AuthFileName)
	if err := os.Remove(authPath); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove auth file %s: %v", authPath, err)
	} else {
		log.Infof("Removed auth file: %s", authPath)
	}
}

// WriteDeactivatedMarker writes a marker file next to the binary indicating
// the agent was deactivated. The install scripts or startup logic can check
// for this file to prevent restart loops.
func WriteDeactivatedMarker(reason string) {
	exe, err := os.Executable()
	if err != nil {
		log.Warnf("Cannot determine executable path for deactivation marker: %v", err)
		return
	}
	markerPath := filepath.Join(filepath.Dir(exe), "DEACTIVATED")
	content := fmt.Sprintf("Agent deactivated at %s\nReason: %s\n", time.Now().Format(time.RFC3339), reason)
	if err := os.WriteFile(markerPath, []byte(content), 0644); err != nil {
		log.Warnf("Failed to write deactivation marker: %v", err)
	} else {
		log.Infof("Wrote deactivation marker: %s", markerPath)
	}
}

// SelfUninstall performs platform-specific cleanup to decommission the agent.
// It directly stops/removes the system service and cleans up files — no external
// install scripts are required.
//
// Service names and paths match the conventions from install.sh / install.ps1:
//   - Linux:   systemd service "netwatcher-agent", install dir /opt/netwatcher-agent
//   - Windows: sc service "NetWatcherAgent", install dir determined from executable path
func SelfUninstall(reason string) {
	log.Warnf("Performing self-uninstall (reason: %s)", reason)

	// Remove credentials and write marker first — even if service cleanup fails,
	// the marker prevents restart loops.
	RemoveAuthFile()
	WriteDeactivatedMarker(reason)

	switch runtime.GOOS {
	case "linux", "darwin":
		// 1) Stop the systemd service
		log.Info("[uninstall] Stopping netwatcher-agent service...")
		if out, err := exec.Command("systemctl", "stop", "netwatcher-agent").CombinedOutput(); err != nil {
			log.Debugf("[uninstall] systemctl stop: %s (%v)", string(out), err)
		}

		// 2) Disable so it doesn't start on boot
		log.Info("[uninstall] Disabling netwatcher-agent service...")
		if out, err := exec.Command("systemctl", "disable", "netwatcher-agent").CombinedOutput(); err != nil {
			log.Debugf("[uninstall] systemctl disable: %s (%v)", string(out), err)
		}

		// 3) Remove the systemd unit file
		serviceFile := "/etc/systemd/system/netwatcher-agent.service"
		if err := os.Remove(serviceFile); err != nil && !os.IsNotExist(err) {
			log.Warnf("[uninstall] Could not remove %s: %v", serviceFile, err)
		} else {
			log.Infof("[uninstall] Removed %s", serviceFile)
		}

		// 4) Reload systemd daemon so it forgets the unit
		_ = exec.Command("systemctl", "daemon-reload").Run()

		log.Info("[uninstall] Linux service cleanup complete")

	case "windows":
		// 1) Stop the Windows service
		log.Info("[uninstall] Stopping NetWatcherAgent service...")
		if out, err := exec.Command("sc", "stop", "NetWatcherAgent").CombinedOutput(); err != nil {
			log.Debugf("[uninstall] sc stop: %s (%v)", string(out), err)
		}

		// 2) Delete the service registration
		log.Info("[uninstall] Deleting NetWatcherAgent service...")
		if out, err := exec.Command("sc", "delete", "NetWatcherAgent").CombinedOutput(); err != nil {
			log.Debugf("[uninstall] sc delete: %s (%v)", string(out), err)
		}

		log.Info("[uninstall] Windows service cleanup complete")

	default:
		log.Warnf("[uninstall] Platform %s has no service to remove — credentials cleared and marker written", runtime.GOOS)
	}
}
