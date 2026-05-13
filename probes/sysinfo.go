package probes

import (
	"encoding/json"
	"github.com/elastic/go-sysinfo"
	"github.com/netwatcherio/netwatcher-agent/nettime"
	"time"
)

type CompleteSystemInfo struct {
	HostInfo   HostInfo       `json:"hostInfo"`
	MemoryInfo HostMemoryInfo `json:"memoryInfo"`
	CPUTimes   CPUTimes       `json:"CPUTimes"`
	Timestamp  time.Time      `json:"timestamp"`
}

type CPUTimes struct {
	User    time.Duration `json:"user"`
	System  time.Duration `json:"system"`
	Idle    time.Duration `json:"idle,omitempty"`
	IOWait  time.Duration `json:"iowait,omitempty"`
	IRQ     time.Duration `json:"irq,omitempty"`
	Nice    time.Duration `json:"nice,omitempty"`
	SoftIRQ time.Duration `json:"soft_irq,omitempty"`
	Steal   time.Duration `json:"steal,omitempty"`
}

type HostInfo struct {
	Architecture      string    `json:"architecture"`
	BootTime          time.Time `json:"boot_time"`
	Containerized     *bool     `json:"containerized,omitempty"`
	Hostname          string    `json:"name"`
	IPs               []string  `json:"ip,omitempty"`
	KernelVersion     string    `json:"kernel_version"`
	MACs              []string  `json:"mac"`
	OS                OSInfo    `json:"os"`
	Timezone          string    `json:"timezone"`
	TimezoneOffsetSec int       `json:"timezone_offset_sec"`
	UniqueID          string    `json:"id,omitempty"`
}

type OSInfo struct {
	Type     string `json:"type"`
	Family   string `json:"family"`
	Platform string `json:"platform"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Major    int    `json:"major"`
	Minor    int    `json:"minor"`
	Patch    int    `json:"patch"`
	Build    string `json:"build,omitempty"`
	Codename string `json:"codename,omitempty"`
}

// HostMemoryInfo (all values are specified in bytes).
type HostMemoryInfo struct {
	Total        uint64            `json:"total_bytes"`         // Total physical memory.
	Used         uint64            `json:"used_bytes"`          // Total - Free
	Available    uint64            `json:"available_bytes"`     // Amount of memory available without swapping.
	Free         uint64            `json:"free_bytes"`          // Amount of memory not used by the system.
	VirtualTotal uint64            `json:"virtual_total_bytes"` // Total virtual memory.
	VirtualUsed  uint64            `json:"virtual_used_bytes"`  // VirtualTotal - VirtualFree
	VirtualFree  uint64            `json:"virtual_free_bytes"`  // Virtual memory that is not used.
	Metrics      map[string]uint64 `json:"raw,omitempty"`       // Other memory related metrics.
}

func SystemInfo() (CompleteSystemInfo, error) {
	var n CompleteSystemInfo
	n.Timestamp = nettime.AdjustedTime()

	host, err := sysinfo.Host()

	marshalHost, err := json.Marshal(host.Info())
	if err != nil {
		return n, err
	}

	var hostInfo = HostInfo{}
	err = json.Unmarshal(marshalHost, &hostInfo)
	if err != nil {
		return n, err
	}

	n.HostInfo = hostInfo

	memory, err := host.Memory()
	if err != nil {
		return n, err
	}

	marshalMemory, err := json.Marshal(memory)
	if err != nil {
		return n, err
	}

	var memoryInfo = HostMemoryInfo{}
	err = json.Unmarshal(marshalMemory, &memoryInfo)
	if err != nil {
		return n, err
	}

	n.MemoryInfo = memoryInfo

	cpuTimer, err := host.CPUTime()
	if err != nil {
		return n, err
	}

	cpuMarshal, err := json.Marshal(cpuTimer)
	if err != nil {
		return n, err
	}

	var cpuTimeInfo = CPUTimes{}
	err = json.Unmarshal(cpuMarshal, &cpuTimeInfo)
	if err != nil {
		return n, err
	}

	n.CPUTimes = cpuTimeInfo

	return n, nil
}
