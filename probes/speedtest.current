package probes

import (
	"encoding/json"
	"github.com/showwin/speedtest-go/speedtest"
	"github.com/showwin/speedtest-go/speedtest/transport"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"
)

type SpeedTestResult struct {
	TestData  []speedtest.Server `json:"test_data"`
	Timestamp time.Time          `json:"timestamp" bson:"timestamp"`
}

type Server struct {
	URL          string          `xml:"url,attr" json:"url"`
	Lat          string          `xml:"lat,attr" json:"lat"`
	Lon          string          `xml:"lon,attr" json:"lon"`
	Name         string          `xml:"name,attr" json:"name"`
	Country      string          `xml:"country,attr" json:"country"`
	Sponsor      string          `xml:"sponsor,attr" json:"sponsor"`
	ID           string          `xml:"id,attr" json:"id"`
	Host         string          `xml:"host,attr" json:"host"`
	Distance     float64         `json:"distance"`
	Latency      time.Duration   `json:"latency"`
	MaxLatency   time.Duration   `json:"max_latency"`
	MinLatency   time.Duration   `json:"min_latency"`
	Jitter       time.Duration   `json:"jitter"`
	DLSpeed      ByteRate        `json:"dl_speed"`
	ULSpeed      ByteRate        `json:"ul_speed"`
	TestDuration TestDuration    `json:"test_duration"`
	PacketLoss   transport.PLoss `json:"packet_loss"`
}

type ByteRate float64

type TestDuration struct {
	Ping     *time.Duration `json:"ping"`
	Download *time.Duration `json:"download"`
	Upload   *time.Duration `json:"upload"`
	Total    *time.Duration `json:"total"`
}

type PLoss struct {
	Sent int `json:"sent"` // Number of sent packets acknowledged by the remote.
	Dup  int `json:"dup"`  // Number of duplicate packets acknowledged by the remote.
	Max  int `json:"max"`  // The maximum index value received by the remote.
}

func SpeedTest(cd *Probe) (SpeedTestResult, error) {
	var s1 []speedtest.Server
	var speedtestClient = speedtest.New()

	// Use a proxy for the speedtest. eg: socks://127.0.0.1:7890
	// speedtest.WithUserConfig(&speedtest.UserConfig{Proxy: "socks://127.0.0.1:7890"})(speedtestClient)

	// Select a network card as the data interface.
	// speedtest.WithUserConfig(&speedtest.UserConfig{Source: "192.168.1.101"})(speedtestClient)

	// Get user's network information
	// user, _ := speedtestClient.FetchUserInfo()

	// Get a list of servers near a specified location
	// user.SetLocationByCity("Tokyo")
	// user.SetLocation("Osaka", 34.6952, 135.5006)

	// Search server using serverID.
	// eg: fetch server with ID 28910.
	// speedtest.ErrServerNotFound will be returned if the server cannot be found.
	// server, err := speedtest.FetchServerByID("28910")

	serverList, _ := speedtestClient.FetchServers()
	var targets []*speedtest.Server

	primaryTarget := cd.Config.Target[0].Target
	if cd.Config.Target[0].Target == "" {
		targets2, _ := serverList.FindServer([]int{})
		targets = append(targets, targets2...)

	} else if primaryTarget != "" && primaryTarget != "expired" && primaryTarget != "ok" {
		atoi, err := strconv.Atoi(cd.Config.Target[0].Target)
		if err != nil {
			return SpeedTestResult{}, err
		}
		targets2, _ := serverList.FindServer([]int{atoi})
		targets = append(targets, targets2...)
	}

	for _, s := range targets {
		// Please make sure your host can access this test server,
		// otherwise you will get an error.
		// It is recommended to replace a server at this time
		err := s.PingTest(nil)
		if err != nil {
			return SpeedTestResult{}, err
		}
		err = s.DownloadTest()
		if err != nil {
			return SpeedTestResult{}, err
		}
		err = s.UploadTest()
		if err != nil {
			return SpeedTestResult{}, err
		}

		s1 = append(s1, *s)
		s.Context.Reset() // reset counter
	}

	result := SpeedTestResult{
		TestData:  s1,
		Timestamp: time.Now(),
	}

	marshal, err := json.Marshal(result)
	if err != nil {
		return SpeedTestResult{}, err
	}

	log.Warnf("%s", marshal)

	return result, nil
}
