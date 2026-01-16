package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/netwatcherio/netwatcher-agent/lib/platform"
	"github.com/netwatcherio/netwatcher-agent/lib/tracert"
	log "github.com/sirupsen/logrus"
)

// useTracertFallback tracks whether Trippy has failed and we should use tracert directly
// This is a "sticky" fallback - once Trippy fails, we use tracert for all subsequent tests
var (
	useTracertFallback bool
	fallbackMu         sync.RWMutex
)

// setTracertFallback sets the fallback flag (thread-safe)
func setTracertFallback() {
	fallbackMu.Lock()
	defer fallbackMu.Unlock()
	if !useTracertFallback {
		useTracertFallback = true
		log.Warn("Trippy fallback activated - will use Windows tracert for all future MTR tests")
	}
}

// shouldUseTracert returns true if we should skip Trippy and use tracert directly
func shouldUseTracert() bool {
	fallbackMu.RLock()
	defer fallbackMu.RUnlock()
	return useTracertFallback && platform.IsWindows()
}

type MtrPayload struct {
	StartTimestamp time.Time `json:"start_timestamp"bson:"start_timestamp"`
	StopTimestamp  time.Time `json:"stop_timestamp"bson:"stop_timestamp"`
	Report         struct {
		Info struct {
			Target struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"target"`
		} `json:"info"`
		Hops []struct {
			TTL   int `json:"ttl"`
			Hosts []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"hosts"`
			Extensions []string `json:"extensions"`
			LossPct    string   `json:"loss_pct"`
			Sent       int      `json:"sent"`
			Last       string   `json:"last"`
			Recv       int      `json:"recv"`
			Avg        string   `json:"avg"`
			Best       string   `json:"best"`
			Worst      string   `json:"worst"`
			StdDev     string   `json:"stddev"`
		} `json:"hops"`
	} `json:"report"bson:"report"`
}

/*type MtrPayload struct {
	StartTimestamp time.Time `json:"start_timestamp"bson:"start_timestamp"`
	StopTimestamp  time.Time `json:"stop_timestamp"bson:"stop_timestamp"`
	Triggered      bool      `bson:"triggered"json:"triggered"`
	Report         struct {
		Mtr struct {
			Src        string      `json:"src"bson:"src"`
			Dst        string      `json:"dst"bson:"dst"`
			Tos        interface{} `json:"tos"bson:"tos"`
			Tests      interface{} `json:"tests"bson:"tests"`
			Psize      string      `json:"psize"bson:"psize"`
			Bitpattern string      `json:"bitpattern"bson:"bitpattern"`
		} `json:"mtr"bson:"mtr"`
		Hubs []struct {
			Count interface{} `json:"count"bson:"count"`
			Host  string      `json:"host"bson:"host"`
			ASN   string      `json:"ASN"bson:"ASN"`
			Loss  float64     `json:"Loss%"bson:"Loss%"`
			Drop  int         `json:"Drop"bson:"Drop"`
			Rcv   int         `json:"Rcv"bson:"Rcv"`
			Snt   int         `json:"Snt"bson:"Snt"`
			Best  float64     `json:"Best"bson:"Best"`
			Avg   float64     `json:"Avg"bson:"Avg"`
			Wrst  float64     `json:"Wrst"bson:"Wrst"`
			StDev float64     `json:"StDev"bson:"StDev"`
			Gmean float64     `json:"Gmean"bson:"Gmean"`
			Jttr  float64     `json:"Jttr"bson:"Jttr"`
			Javg  float64     `json:"Javg"bson:"Javg"`
			Jmax  float64     `json:"Jmax"bson:"Jmax"`
			Jint  float64     `json:"Jint"bson:"Jint"`
		} `json:"hubs"bson:"hubs"`
	} `json:"report"bson:"report"`
}*/

// Mtr run the check for mtr, take input from checkdata for the test, and update the mtrresult object
func Mtr(cd *Probe, triggered bool) (MtrPayload, error) {
	var mtrResult MtrPayload
	mtrResult.StartTimestamp = time.Now()

	triggeredCount := 5
	if triggered {
		triggeredCount = 15
	}

	// Use platform package for binary path resolution
	if err := platform.CheckSupported(); err != nil {
		return mtrResult, err
	}

	// If we've previously fallen back to tracert, use it directly
	// This avoids retrying Trippy each time if it's blocked by antivirus, etc.
	if shouldUseTracert() {
		log.Debug("Using Windows tracert (sticky fallback active)")
		return runTracert(cd, triggeredCount)
	}

	trippyPath := platform.BinaryPath("trip")

	/*args := []string{
		"--icmp",
		"--mode json",
		"--multipath-strategy dublin",
		"--dns-resolve-method cloudflare",
		"--dns-lookup-as-info",
		"--report-cycles " + strconv.Itoa(triggeredCount),
		cd.Config.Target[0].Target,
	}*/

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(120)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if platform.IsWindows() {
		// Use exec.Command directly - no shell needed, handles paths with spaces correctly
		cmd = exec.CommandContext(ctx, trippyPath,
			"--icmp",
			"--mode", "json",
			"--multipath-strategy", "classic",
			"--dns-resolve-method", "system",
			"--report-cycles", strconv.Itoa(triggeredCount),
			/*"--dns-lookup-as-info",*/
			cd.Targets[0].Target)
	} else {
		// For Linux and macOS, use exec.Command directly as well
		cmd = exec.CommandContext(ctx, trippyPath,
			"--icmp",
			"--mode", "json",
			"--multipath-strategy", "classic",
			"--dns-resolve-method", "system",
			"--report-cycles", strconv.Itoa(triggeredCount),
			/*"--dns-lookup-as-info",*/
			cd.Targets[0].Target)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Log both the error and any output for debugging
		log.WithFields(log.Fields{
			"error":  err.Error(),
			"output": string(output),
			"target": cd.Targets[0].Target,
			"path":   trippyPath,
		}).Error("Trip execution failed")

		// On Windows, fall back to tracert if Trippy fails
		// This handles cases like antivirus blocking, permission issues, or missing binary
		if platform.IsWindows() {
			setTracertFallback() // Remember to use tracert for future tests
			log.WithField("target", cd.Targets[0].Target).Warn("Falling back to Windows tracert")
			return runTracert(cd, triggeredCount)
		}

		return mtrResult, fmt.Errorf("%w: %s", err, string(output))
	}

	err = json.Unmarshal(output, &mtrResult.Report)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err.Error(),
			"output": string(output),
		}).Error("Failed to parse trip output")

		// On Windows, fall back to tracert if Trippy output is malformed
		if platform.IsWindows() {
			setTracertFallback() // Remember to use tracert for future tests
			log.WithField("target", cd.Targets[0].Target).Warn("Trippy output malformed, falling back to Windows tracert")
			return runTracert(cd, triggeredCount)
		}

		return mtrResult, err
	}

	mtrResult.StopTimestamp = time.Now()
	return mtrResult, nil
}

// runTracert executes Windows tracert and converts output to MtrPayload format.
func runTracert(cd *Probe, maxHops int) (MtrPayload, error) {
	var mtrResult MtrPayload
	mtrResult.StartTimestamp = time.Now()

	target := cd.Targets[0].Target

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(120)*time.Second)
	defer cancel()

	result, err := tracert.Run(ctx, target, maxHops)
	if err != nil {
		log.WithFields(log.Fields{
			"error":  err.Error(),
			"target": target,
		}).Error("Windows tracert failed")
		return mtrResult, err
	}

	// Convert tracert result to MtrPayload format
	mtrResult.Report.Info.Target.IP = result.TargetIP
	mtrResult.Report.Info.Target.Hostname = result.TargetHostname

	for _, hop := range result.Hops {
		hopData := struct {
			TTL   int `json:"ttl"`
			Hosts []struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			} `json:"hosts"`
			Extensions []string `json:"extensions"`
			LossPct    string   `json:"loss_pct"`
			Sent       int      `json:"sent"`
			Last       string   `json:"last"`
			Recv       int      `json:"recv"`
			Avg        string   `json:"avg"`
			Best       string   `json:"best"`
			Worst      string   `json:"worst"`
			StdDev     string   `json:"stddev"`
		}{
			TTL:        hop.TTL,
			Extensions: []string{},
			LossPct:    fmt.Sprintf("%.2f", hop.LossPct),
			Sent:       hop.Sent,
			Recv:       hop.Recv,
			StdDev:     "0.00", // tracert doesn't provide stddev
		}

		// Add host if IP is present
		if hop.IP != "" {
			hopData.Hosts = append(hopData.Hosts, struct {
				IP       string `json:"ip"`
				Hostname string `json:"hostname"`
			}{
				IP:       hop.IP,
				Hostname: hop.Hostname,
			})
		}

		// Format latencies
		if hop.Recv > 0 {
			// Use avg as "last" since tracert doesn't track individual samples
			hopData.Last = fmt.Sprintf("%.2f", hop.Avg)
			hopData.Avg = fmt.Sprintf("%.2f", hop.Avg)
			hopData.Best = fmt.Sprintf("%.2f", hop.Best)
			hopData.Worst = fmt.Sprintf("%.2f", hop.Worst)
		} else {
			hopData.Last = "0.00"
			hopData.Avg = "0.00"
			hopData.Best = "0.00"
			hopData.Worst = "0.00"
		}

		mtrResult.Report.Hops = append(mtrResult.Report.Hops, hopData)
	}

	mtrResult.StopTimestamp = time.Now()

	log.WithFields(log.Fields{
		"target": target,
		"hops":   len(mtrResult.Report.Hops),
	}).Info("Windows tracert completed successfully")

	return mtrResult, nil
}

func mtrNumDashCheck(str string) int {
	if str == "-" {
		return 0
	}
	return ConvHandleStrInt(str)
}
