package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/kataras/iris/v12/websocket"
	"github.com/netwatcherio/netwatcher-agent/probes"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kataras/neffos"
	"github.com/kataras/neffos/gobwas"
	log "github.com/sirupsen/logrus"
)

/*
ENV VARS:

  NW_AGENT_API_URL         e.g. http://localhost:8080/api/agent
  NW_AGENT_WS_URL          e.g. ws://localhost:8080/ws
  NW_AGENT_WORKSPACE_ID    uint
  NW_AGENT_AGENT_ID        uint
  NW_AGENT_PIN             optional (used if PSK missing)
  NW_AGENT_PSK             optional (preferred)

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

type LoginResponse struct {
	Status string       `json:"status"`          // "ok" | "bootstrapped"
	PSK    string       `json:"psk,omitempty"`   // only on bootstrap
	Agent  *agent.Agent `json:"agent,omitempty"` // convenience
	Error  string       `json:"error,omitempty"` // on failure
}

// --- API payloads (minimal; we keep raw for persistence) ---

type agentLoginRequest struct {
	WorkspaceID uint   `json:"workspaceId,omitempty"`
	AgentID     uint   `json:"agentId,omitempty"`
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
	APIURL      string
	WSURL       string
	WorkspaceID uint
	AgentID     uint
	PIN         string
	PSK         string
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

func LoadConfigFromEnv() Config {
	return Config{
		APIURL:      mustEnv("API_URL"),
		WSURL:       mustEnv("WS_URL"),
		WorkspaceID: parseUintEnv("WORKSPACE_ID"),
		AgentID:     parseUintEnv("AGENT_ID"),
		PIN:         strings.TrimSpace(os.Getenv("AGENT_PIN")),
		PSK:         strings.TrimSpace(os.Getenv("AGENT_PSK")),
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
		return nil, fmt.Errorf("login decode: %w", err)
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
	URL         string
	WorkspaceID uint
	AgentID     uint
	PSK         string
	ProbeGetCh  chan []probes.Probe
	WsConn      *neffos.NSConn
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
				return nil
			},
			neffos.OnNamespaceDisconnect: func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: disconnected from namespace [%s]", msg.Namespace)
				return nil
			},
			"probe_get": func(ns *neffos.NSConn, msg neffos.Message) error {
				log.Infof("WS: received probe_get: %s", string(msg.Body))
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
