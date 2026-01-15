package probes

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"time"

	"github.com/netwatcherio/netwatcher-agent/lib/platform"
)

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

	/*ctx, cancel := context.WithTimeout(context.Background(), time.Duration(60)*time.Second)
	defer cancel()*/

	var cmd *exec.Cmd
	if platform.IsWindows() {
		shellArgs := append([]string{"/c", trippyPath + " " +
			"--udp " +
			"--mode json " +
			"--multipath-strategy paris " +
			"--dns-resolve-method system " +
			"--report-cycles " + strconv.Itoa(triggeredCount) + " " +
			"--dns-lookup-as-info " + cd.Targets[0].Target})
		cmd = exec.CommandContext(context.TODO(), "cmd.exe", shellArgs...)
	} else {
		// For Linux and macOS, use /bin/bash
		shellArgs := append([]string{"-c", trippyPath + " --udp --mode json --multipath-strategy paris --dns-resolve-method system --report-cycles " + strconv.Itoa(triggeredCount) + " --dns-lookup-as-info " + cd.Targets[0].Target})
		cmd = exec.CommandContext(context.TODO(), "/bin/bash", shellArgs...)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return mtrResult, err
	}

	err = json.Unmarshal(output, &mtrResult.Report)
	if err != nil {
		return mtrResult, err
	}

	mtrResult.StopTimestamp = time.Now()
	return mtrResult, nil
}

func mtrNumDashCheck(str string) int {
	if str == "-" {
		return 0
	}
	return ConvHandleStrInt(str)
}
