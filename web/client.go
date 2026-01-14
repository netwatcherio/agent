package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/iris/v12/websocket"
	"github.com/netwatcherio/netwatcher-agent/probes"

	"github.com/kataras/neffos"
	"github.com/kataras/neffos/gobwas"
	log "github.com/sirupsen/logrus"
)

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
	Status string `json:"status"`          // "ok" | "bootstrapped"
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
				c.ConnectWithRetry(context.Background())
				return nil
			},
			"probe_get": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: received probe_get: %s", string(msg.Body))
				var p []probes.Probe

				if err := json.Unmarshal(msg.Body, &p); err != nil {
					return err
				}
				c.ProbeGetCh <- p
				return nil
			},
			"speedtest_servers_ok": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: speedtest_servers acknowledged: %s", string(msg.Body))
				return nil
			},
			"speedtest_queue": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: received speedtest_queue: %s", string(msg.Body))
				var items []probes.SpeedtestQueueItem
				if err := json.Unmarshal(msg.Body, &items); err != nil {
					log.Errorf("WS: failed to unmarshal speedtest_queue: %v", err)
					return err
				}
				if c.SpeedtestQueueCh != nil {
					c.SpeedtestQueueCh <- items
				}
				return nil
			},
			"speedtest_result_ok": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: speedtest_result acknowledged: %s", string(msg.Body))
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
