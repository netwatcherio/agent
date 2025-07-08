package probes

import (
	"context"
	"encoding/json"
	"fmt"
	probing "github.com/prometheus-community/pro-bing"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"os"
	"runtime"
	"time"
)

type PingResult struct {
	// StartTime is the time that the check started at
	StartTimestamp time.Time `json:"start_timestamp"bson:"start_timestamp"`
	StopTimestamp  time.Time `json:"stop_timestamp"bson:"stop_timestamp"`
	// PacketsRecv is the number of packets received.
	PacketsRecv int `json:"packets_recv"bson:"packets_recv"`
	// PacketsSent is the number of packets sent.
	PacketsSent int `json:"packets_sent"bson:"packets_sent"`
	// PacketsRecvDuplicates is the number of duplicate responses there were to a sent packet.
	PacketsRecvDuplicates int `json:"packets_recv_duplicates"bson:"packets_recv_duplicates"`
	// PacketLoss is the percentage of packets lost.
	PacketLoss float64 `json:"packet_loss"bson:"packet_loss"`
	// Addr is the string address of the host being pinged.
	Addr string `json:"addr"bson:"addr"`
	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration `json:"min_rtt"bson:"min_rtt"`
	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration `json:"max_rtt"bson:"max_rtt"`
	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration `json:"avg_rtt"bson:"avg_rtt"`
	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration `json:"std_dev_rtt"bson:"std_dev_rtt"`
}

func Ping(ac *Probe, pingChan chan ProbeData, mtrProbe Probe) error {
	startTime := time.Now()

	pinger, err := probing.NewPinger(ac.Config.Target[0].Target)
	if err != nil {
		fmt.Println(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(2*ac.Config.Duration)*time.Second)
	defer cancel()

	osDetect := runtime.GOOS

	switch osDetect {
	case "windows":
		pinger.Size = 548
		pinger.SetPrivileged(true)
		break
	case "darwin":
		pinger.SetPrivileged(true)
		break
	case "linux":
		pinger.SetPrivileged(true)
		break
	default:
		log.Fatalf("Unknown OS")
		panic("TODO")
	}

	pinger.Count = ac.Config.Duration

	/*pinger.OnRecv = func(pkt *probing.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}*/

	pinger.OnFinish = func(stats *probing.Statistics) {

		pingR := PingResult{
			StartTimestamp:        startTime,
			StopTimestamp:         time.Now(),
			PacketsRecv:           stats.PacketsRecv,
			PacketsSent:           stats.PacketsSent,
			PacketsRecvDuplicates: stats.PacketsRecvDuplicates,
			PacketLoss:            stats.PacketLoss,
			Addr:                  stats.Addr,
			MinRtt:                time.Duration(stats.MinRtt.Nanoseconds()),
			MaxRtt:                time.Duration(stats.MaxRtt.Nanoseconds()),
			AvgRtt:                time.Duration(stats.AvgRtt.Nanoseconds()),
			StdDevRtt:             time.Duration(stats.StdDevRtt.Nanoseconds()),
		}

		/*fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
			stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)*/

		marshal, err := json.Marshal(pingR)
		if err != nil {
			//return
		}

		log.Info(string(marshal))

		reportingAgent, err := primitive.ObjectIDFromHex(os.Getenv("ID"))
		if err != nil {
			log.Printf("TrafficSim: Failed to get reporting agent ID: %v", err)
			return
		}

		cD := ProbeData{
			ProbeID: ac.ID,
			Data:    pingR,
			Target: ProbeTarget{
				Target: string(ProbeType_PING) + "%%%" + mtrProbe.Config.Target[0].Target,
				Agent:  mtrProbe.Config.Target[0].Agent,
				Group:  reportingAgent,
			},
		}

		pingChan <- cD

		// todo configurable threshold
		if pingR.PacketLoss > 2 {
			if len(mtrProbe.Config.Target) > 0 {

				mtr, err := Mtr(&mtrProbe, true)
				if err != nil {
					fmt.Println(err)
				}

				dC := ProbeData{
					ProbeID:   mtrProbe.ID,
					Triggered: true,
					Data:      mtr,
					Target: ProbeTarget{
						Target: string(ProbeType_MTR) + "%%%" + mtrProbe.Config.Target[0].Target,
						Agent:  mtrProbe.Config.Target[0].Agent,
						Group:  reportingAgent,
					},
				}

				fmt.Println("Triggered MTR for ", mtrProbe.Config.Target[0].Target, "...")
				pingChan <- dC
			}
		}
	}

	err = pinger.RunWithContext(ctx) // Blocks until finished.
	if err != nil {
		log.Error(err)
		return err
	}

	//stats := pinger.Statistics() // get send/receive/duplicate/rtt stats

	/*fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
	fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
		stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
	fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
		stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)*/

	//pingChan <- cD

	return nil
}
