package probes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type RPerfResults struct {
	StartTimestamp time.Time `json:"start_timestamp"bson:"start_timestamp"`
	StopTimestamp  time.Time `json:"stop_timestamp"bson:"stop_timestamp"`
	Config         struct {
		Additional struct {
			IpVersion   int  `json:"ip_version"bson:"ip_version"`
			OmitSeconds int  `json:"omit_seconds"bson:"omit_seconds"`
			Reverse     bool `json:"reverse"bson:"reverse"`
		} `json:"additional"bson:"additional"`
		Common struct {
			Family  string `json:"family"bson:"family"`
			Length  int    `json:"length"bson:"length"`
			Streams int    `json:"streams"bson:"streams"`
		} `json:"common"bson:"common"`
		Download struct {
		} `json:"download"bson:"download"`
		Upload struct {
			Bandwidth    int     `json:"bandwidth"bson:"bandwidth"`
			Duration     float64 `json:"duration"bson:"duration"`
			SendInterval float64 `json:"send_interval"bson:"send_interval"`
		} `json:"upload"bson:"upload"`
	} `json:"config"bson:"config"`
	/*Streams []struct {
		Abandoned bool `json:"abandoned"bson:"abandoned"`
		Failed    bool `json:"failed"bson:"failed"`
		Intervals struct {
			Receive []struct {
				BytesReceived     int     `json:"bytes_received"bson:"bytes_received"`
				Duration          float64 `json:"duration"bson:"duration"`
				JitterSeconds     float64 `json:"jitter_seconds"bson:"jitter_seconds"`
				PacketsDuplicated int     `json:"packets_duplicated"bson:"packets_duplicated"`
				PacketsLost       int     `json:"packets_lost"bson:"packets_lost"`
				PacketsOutOfOrder int     `json:"packets_out_of_order"bson:"packets_out_of_order"`
				PacketsReceived   int     `json:"packets_received"bson:"packets_received"`
				Timestamp         float64 `json:"timestamp"bson:"timestamp"`
				UnbrokenSequence  int     `json:"unbroken_sequence"bson:"unbroken_sequence"`
			} `json:"receive"bson:"receive"`
			Send []struct {
				BytesSent    int     `json:"bytes_sent"bson:"bytes_sent"`
				Duration     float64 `json:"duration"bson:"duration"`
				PacketsSent  int     `json:"packets_sent"bson:"packets_sent"`
				SendsBlocked int     `json:"sends_blocked"bson:"sends_blocked"`
				Timestamp    float64 `json:"timestamp"bson:"timestamp"`
			} `json:"send"bson:"send"`
			Summary struct {
				BytesReceived            int     `json:"bytes_received"bson:"bytes_received"`
				BytesSent                int     `json:"bytes_sent"bson:"bytes_sent"`
				DurationReceive          float64 `json:"duration_receive"bson:"duration_receive"`
				DurationSend             float64 `json:"duration_send"bson:"duration_send"`
				FramedPacketSize         int     `json:"framed_packet_size"bson:"framed_packet_size"`
				JitterAverage            float64 `json:"jitter_average"bson:"jitter_average"`
				JitterPacketsConsecutive int     `json:"jitter_packets_consecutive"bson:"jitter_packets_consecutive"`
				PacketsDuplicated        int     `json:"packets_duplicated"bson:"packets_duplicated"`
				PacketsLost              int     `json:"packets_lost"bson:"packets_lost"`
				PacketsOutOfOrder        int     `json:"packets_out_of_order"bson:"packets_out_of_order"`
				PacketsReceived          int     `json:"packets_received"bson:"packets_received"`
				PacketsSent              int     `json:"packets_sent"bson:"packets_sent"`
			} `json:"summary"bson:"summary"`
		} `json:"intervals"bson:"intervals"`
	} `json:"streams"bson:"streams"`*/
	Success bool `json:"success"bson:"success"`
	Summary struct {
		BytesReceived            int     `json:"bytes_received"bson:"bytes_received"`
		BytesSent                int     `json:"bytes_sent"bson:"bytes_sent"`
		DurationReceive          float64 `json:"duration_receive"bson:"duration_receive"`
		DurationSend             float64 `json:"duration_send"bson:"duration_send"`
		FramedPacketSize         int     `json:"framed_packet_size"bson:"framed_packet_size"`
		JitterAverage            float64 `json:"jitter_average"bson:"jitter_average"`
		JitterPacketsConsecutive int     `json:"jitter_packets_consecutive"bson:"jitter_packets_consecutive"`
		PacketsDuplicated        int     `json:"packets_duplicated"bson:"packets_duplicated"`
		PacketsLost              int     `json:"packets_lost"bson:"packets_lost"`
		PacketsOutOfOrder        int     `json:"packets_out_of_order"bson:"packets_out_of_order"`
		PacketsReceived          int     `json:"packets_received"bson:"packets_received"`
		PacketsSent              int     `json:"packets_sent"bson:"packets_sent"`
	} `json:"summary"bson:"summary"`
}

//./rperf -c 0.0.0.0 -p 5199 -b 8K -t 10 --udp -f json

func (r *RPerfResults) Run(cd *Probe) error {
	osDetect := runtime.GOOS
	r.StartTimestamp = time.Now()

	var cmd *exec.Cmd
	switch osDetect {
	case "windows":
		targetHost := strings.Split(cd.Config.Target[0].Target, ":")
		args := []string{"-s -p " + targetHost[1]}
		cmd = exec.CommandContext(context.TODO(), "./lib/rperf_windows-x86_64.exe", args...)
		break
	case "darwin":
		targetHost := strings.Split(cd.Config.Target[0].Target, ":")
		args := []string{"-c", "./lib/rperf_darwin -s -p " + targetHost[1]}
		cmd = exec.CommandContext(context.TODO(), "/bin/bash", args...)
		break
	case "linux":
		targetHost := strings.Split(cd.Config.Target[0].Target, ":")
		args := []string{"-c", "./lib/rperf_linux64 -s -p " + targetHost[1]}
		cmd = exec.CommandContext(context.TODO(), "/bin/bash", args...)
		break
	default:
		log.Print("Unknown OS")
	}

	out, err := cmd.CombinedOutput()
	fmt.Printf("%s\n", out)
	if err != nil {
		return err
	}

	return nil
}

func (r *RPerfResults) Check(cd *Probe) error {
	osDetect := runtime.GOOS
	r.StartTimestamp = time.Now()

	// todo make this p2p???

	var cmd *exec.Cmd
	switch osDetect {
	case "windows":
		targetHost := strings.Split(cd.Config.Target[0].Target, ":")
		args := []string{"-c", targetHost[0], "-p", targetHost[1], "-b", "8K", "-t", strconv.Itoa(cd.Config.Duration), "--udp", "--format", "json"}
		cmd = exec.CommandContext(context.TODO(), "./lib/rperf_windows-x86_64.exe", args...)
		break
	case "darwin":
		targetHost := strings.Split(cd.Config.Target[0].Target, ":")
		args := []string{"-c", "./lib/rperf_darwin -c " + targetHost[0] + " -p " + targetHost[1] + " -b 8K -t " + strconv.Itoa(cd.Config.Duration) + " --udp -f json"}
		cmd = exec.CommandContext(context.TODO(), "/bin/bash", args...)
		break
	case "linux":
		targetHost := strings.Split(cd.Config.Target[0].Target, ":")
		args := []string{"-c", "./lib/rperf_linux64 -c " + targetHost[0] + " -p " + targetHost[1] + " -b 8K -t " + strconv.Itoa(cd.Config.Duration) + " --udp -f json"}
		cmd = exec.CommandContext(context.TODO(), "/bin/bash", args...)
		break
	default:
		log.Print("Unknown OS")
	}

	out, err := cmd.CombinedOutput()
	fmt.Printf("%s\n", out)
	if err != nil {
		return err
	}

	lineN := -1

	beforeJson := ""

	lines := strings.Split(string(out), "\n")
	for n, l := range lines {
		if l != "{" {
			beforeJson += l + "\n"
		} else {
			lineN = n
			break
		}
	}

	if lineN == -1 {
		return errors.New("something went wrong")
	}

	justJson := strings.ReplaceAll(string(out), beforeJson, "")

	r.StopTimestamp = time.Now()
	err = json.Unmarshal([]byte(justJson), &r)
	if err != nil {
		return err
	}

	return nil
}
