package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	agentVersionInfo = "dev"
)

func SetAgentVersion(v string) {
	agentVersionInfo = v
}

var (
	agentUptime = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "netwatcher_agent",
		Name:      "uptime_seconds",
		Help:      "Agent uptime in seconds",
	})

	agentVersion = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "netwatcher_agent",
		Name:      "info",
		Help:      "Agent info",
		ConstLabels: prometheus.Labels{
			"version": agentVersionInfo,
		},
	})

	agentProbesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "netwatcher_agent",
		Subsystem: "probes",
		Name:      "total",
		Help:      "Total number of probes assigned to this agent",
	})

	agentWSConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "netwatcher_agent",
		Name:      "websocket_connected",
		Help:      "WebSocket connection status (1=connected, 0=disconnected)",
	})

	agentProbeDataTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "netwatcher_agent",
		Subsystem: "probe_data",
		Name:      "total",
		Help:      "Total number of probe data points emitted",
	}, []string{"type"})
)

type MetricsServer struct {
	port    int
	server  *http.Server
	enabled bool
}

var metricsServer *MetricsServer
var startTime = time.Now()
var wsConnected atomic.Bool

func SetWSConnected(connected bool) {
	wsConnected.Store(connected)
	if connected {
		agentWSConnected.Set(1)
	} else {
		agentWSConnected.Set(0)
	}
}

func SetProbeCount(count int) {
	agentProbesTotal.Set(float64(count))
}

func IncProbeData(probeType string) {
	agentProbeDataTotal.WithLabelValues(probeType).Inc()
}

func (m *MetricsServer) Start() error {
	if !m.enabled {
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	m.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", m.port),
		Handler: mux,
	}

	go func() {
		log.Infof("Agent metrics server listening on :%d", m.port)
		if err := m.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warnf("Metrics server error: %v", err)
		}
	}()

	return nil
}

func (m *MetricsServer) Stop(ctx context.Context) error {
	if m.server == nil {
		return nil
	}
	return m.server.Shutdown(ctx)
}

func StartMetricsServer() error {
	portStr := os.Getenv("AGENT_METRICS_PORT")
	if portStr == "" || portStr == "0" {
		log.Debug("Agent metrics server disabled (AGENT_METRICS_PORT not set)")
		return nil
	}

	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 || port > 65535 {
		log.Warnf("Invalid AGENT_METRICS_PORT %q, disabling metrics server", portStr)
		return nil
	}

	agentUptime.Set(0)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			agentUptime.Set(time.Since(startTime).Seconds())
		}
	}()

	metricsServer = &MetricsServer{port: port, enabled: true}
	return metricsServer.Start()
}

func StopMetricsServer(ctx context.Context) error {
	if metricsServer == nil {
		return nil
	}
	return metricsServer.Stop(ctx)
}
