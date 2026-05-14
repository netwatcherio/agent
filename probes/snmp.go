package probes

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	log "github.com/sirupsen/logrus"

	"github.com/netwatcherio/netwatcher-agent/nettime"
)

type SNMPConfig struct {
	Version         string   `json:"version"`
	Target          string   `json:"target"`
	Community       string   `json:"community"`
	Retries         int      `json:"retries"`
	TimeoutMs       int      `json:"timeout_ms"`
	OIDs            []string `json:"oids"`
	Profile         string   `json:"profile"`
	UserName        string   `json:"user_name"`
	AuthPassword    string   `json:"auth_password"`
	AuthProtocol    string   `json:"auth_protocol"`
	PrivacyPassword string   `json:"privacy_password"`
	PrivacyProtocol string   `json:"privacy_protocol"`
	SecurityLevel   string   `json:"security_level"`
}

type SNMPPayload struct {
	StartTimestamp time.Time    `json:"start_timestamp"`
	StopTimestamp  time.Time    `json:"stop_timestamp"`
	QueryTimeMs    float64      `json:"query_time_ms"`
	Version        string       `json:"version"`
	Target         string       `json:"target"`
	Profile        string       `json:"profile"`
	Results        []SNMPResult `json:"results"`
	Error          string       `json:"error,omitempty"`
}

type SNMPResult struct {
	OID   string `json:"oid"`
	Value any    `json:"value"`
	Type  string `json:"type"`
	Name  string `json:"name"`
}

var snmpProfiles = map[string][]string{
	"system": {
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
		"1.3.6.1.2.1.1.7.0", // sysServices
	},
	"interface": {
		"1.3.6.1.2.1.2.1.0",    // ifNumber
		"1.3.6.1.2.1.2.2.1.1",  // ifIndex
		"1.3.6.1.2.1.2.2.1.2",  // ifDescr
		"1.3.6.1.2.1.2.2.1.3",  // ifType
		"1.3.6.1.2.1.2.2.1.4",  // ifMtu
		"1.3.6.1.2.1.2.2.1.5",  // ifSpeed
		"1.3.6.1.2.1.2.2.1.7",  // ifAdminStatus
		"1.3.6.1.2.1.2.2.1.8",  // ifOperStatus
		"1.3.6.1.2.1.2.2.1.10", // ifInOctets
		"1.3.6.1.2.1.2.2.1.16", // ifOutOctets
		"1.3.6.1.2.1.2.2.1.13", // ifInDiscards
		"1.3.6.1.2.1.2.2.1.14", // ifInErrors
		"1.3.6.1.2.1.2.2.1.20", // ifOutDiscards
		"1.3.6.1.2.1.2.2.1.19", // ifOutErrors
	},
	"cpu": {
		"1.3.6.1.2.1.25.3.3.1.2", // hrProcessorLoad
	},
	"memory": {
		"1.3.6.1.2.1.25.2.2.0",   // hrMemorySize
		"1.3.6.1.2.1.25.2.3.1.5", // hrStorageSize
		"1.3.6.1.2.1.25.2.3.1.6", // hrStorageUsed
	},
}

func parseSNMPConfig(metadata json.RawMessage) SNMPConfig {
	cfg := SNMPConfig{
		Version:   "2c",
		Community: "public",
		Retries:   3,
		TimeoutMs: 5000,
		Profile:   "system",
		OIDs:      nil,
	}

	if len(metadata) == 0 || string(metadata) == "{}" || string(metadata) == "null" {
		cfg.OIDs = snmpProfiles["system"]
		return cfg
	}

	if err := json.Unmarshal(metadata, &cfg); err != nil {
		log.Warnf("[snmp] failed to parse metadata: %v, using defaults", err)
		return SNMPConfig{
			Version: "2c", Community: "public",
			Retries: 3, TimeoutMs: 5000,
			Profile: "system",
			OIDs:    snmpProfiles["system"],
		}
	}

	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 5000
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}

	if cfg.Profile != "" && cfg.Profile != "custom" {
		if oids, ok := snmpProfiles[cfg.Profile]; ok {
			cfg.OIDs = oids
		}
	}

	if len(cfg.OIDs) == 0 {
		cfg.OIDs = snmpProfiles["system"]
	}

	return cfg
}

func SNMPProbe(probe *Probe, dataChan chan ProbeData) error {
	if len(probe.Targets) == 0 || probe.Targets[0].Target == "" {
		return fmt.Errorf("snmp: no target provided")
	}

	cfg := parseSNMPConfig(probe.Metadata)
	target := cfg.Target
	if target == "" {
		target = probe.Targets[0].Target
	}

	if !strings.Contains(target, ":") {
		target = target + ":161"
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("snmp: invalid target: %w", err)
	}

	port, _ := strconv.ParseUint(portStr, 10, 16)
	if port == 0 {
		port = 161
	}

	startTime := time.Now().Add(nettime.GetTimeOffset())

	params := &gosnmp.GoSNMP{
		Target:  host,
		Port:    uint16(port),
		Retries: cfg.Retries,
		Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		MaxOids: gosnmp.MaxOids,
		Logger:  gosnmp.NewLogger(log.StandardLogger()),
	}

	switch strings.ToLower(cfg.Version) {
	case "1":
		params.Version = gosnmp.Version1
		params.Community = cfg.Community
	case "3":
		params.Version = gosnmp.Version3
		params.SecurityModel = gosnmp.UserSecurityModel
		params.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.UserName,
			AuthenticationProtocol:   parseAuthProtocol(cfg.AuthProtocol),
			PrivacyProtocol:          parsePrivProtocol(cfg.PrivacyProtocol),
			AuthenticationPassphrase: cfg.AuthPassword,
			PrivacyPassphrase:        cfg.PrivacyPassword,
		}
		params.MsgFlags = parseMsgFlags(cfg.SecurityLevel)
	default:
		params.Version = gosnmp.Version2c
		params.Community = cfg.Community
	}

	result := SNMPPayload{
		StartTimestamp: startTime,
		Version:        params.Version.String(),
		Target:         target,
		Profile:        cfg.Profile,
		Results:        []SNMPResult{},
	}

	if err := params.Connect(); err != nil {
		result.Error = fmt.Sprintf("connect failed: %v", err)
		result.StopTimestamp = time.Now().Add(nettime.GetTimeOffset())
		result.QueryTimeMs = float64(result.StopTimestamp.Sub(startTime).Microseconds()) / 1000.0
		emitSNMPResult(probe, dataChan, result)
		return err
	}
	defer params.Conn.Close()

	oids := cfg.OIDs
	if len(oids) == 0 {
		oids = snmpProfiles["system"]
	}

	snmpResults, err := params.Get(oids)
	if err != nil {
		result.Error = fmt.Sprintf("get failed: %v", err)
		result.StopTimestamp = time.Now().Add(nettime.GetTimeOffset())
		result.QueryTimeMs = float64(result.StopTimestamp.Sub(startTime).Microseconds()) / 1000.0
		emitSNMPResult(probe, dataChan, result)
		return err
	}

	result.StopTimestamp = time.Now().Add(nettime.GetTimeOffset())
	result.QueryTimeMs = float64(result.StopTimestamp.Sub(startTime).Microseconds()) / 1000.0

	for _, variable := range snmpResults.Variables {
		result.Results = append(result.Results, parseSNMPVariable(variable))
	}

	log.Infof("[snmp] %s version=%s oids=%d time=%.2fms error=%s",
		target, params.Version.String(), len(oids), result.QueryTimeMs, result.Error)

	emitSNMPResult(probe, dataChan, result)
	return nil
}

func parseAuthProtocol(proto string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(proto) {
	case "SHA", "SHA1":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.MD5
	}
}

func parsePrivProtocol(proto string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(proto) {
	case "AES", "AESCFB128":
		return gosnmp.AES
	case "AES192", "AESCFB192":
		return gosnmp.AES192
	case "AES256", "AESCFB256":
		return gosnmp.AES256
	case "AES192C", "AESCFB192C":
		return gosnmp.AES192C
	case "DES":
		return gosnmp.DES
	default:
		return gosnmp.DES
	}
}

func parseMsgFlags(level string) gosnmp.SnmpV3MsgFlags {
	switch strings.ToLower(level) {
	case "authpriv":
		return gosnmp.AuthPriv | gosnmp.Reportable
	case "authnopriv":
		return gosnmp.AuthNoPriv | gosnmp.Reportable
	default:
		return gosnmp.NoAuthNoPriv | gosnmp.Reportable
	}
}

func parseSNMPVariable(variable gosnmp.SnmpPDU) SNMPResult {
	result := SNMPResult{
		OID:   variable.Name,
		Value: nil,
		Type:  "unknown",
		Name:  oidName(variable.Name),
	}

	switch variable.Type {
	case gosnmp.Integer:
		if v, ok := variable.Value.(uint); ok {
			result.Value = v
			result.Type = "integer"
		} else if v, ok := variable.Value.(int); ok {
			result.Value = v
			result.Type = "integer"
		}
	case gosnmp.OctetString:
		if v, ok := variable.Value.([]byte); ok {
			if isPrintable(v) {
				result.Value = string(v)
				result.Type = "string"
			} else {
				result.Value = hex.EncodeToString(v)
				result.Type = "hex"
			}
		}
	case gosnmp.BitString:
		result.Value = hex.EncodeToString(variable.Value.([]byte))
		result.Type = "bitstring"
	case gosnmp.OpaqueFloat:
		result.Value = variable.Value.(float32)
		result.Type = "float"
	case gosnmp.OpaqueDouble:
		result.Value = variable.Value.(float64)
		result.Type = "double"
	case gosnmp.Counter32:
		if v, ok := variable.Value.(uint); ok {
			result.Value = v
			result.Type = "counter32"
		}
	case gosnmp.Gauge32:
		if v, ok := variable.Value.(uint); ok {
			result.Value = v
			result.Type = "gauge32"
		}
	case gosnmp.Counter64:
		if v, ok := variable.Value.(uint64); ok {
			result.Value = v
			result.Type = "counter64"
		}
	case gosnmp.Uinteger32:
		if v, ok := variable.Value.(uint32); ok {
			result.Value = v
			result.Type = "uinteger32"
		}
	case gosnmp.TimeTicks:
		if v, ok := variable.Value.(uint); ok {
			result.Value = v
			result.Type = "timeticks"
		}
	case gosnmp.ObjectIdentifier:
		result.Value = variable.Value.(string)
		result.Type = "oid"
	case gosnmp.IPAddress:
		result.Value = variable.Value.(string)
		result.Type = "ipaddress"
	default:
		result.Value = fmt.Sprintf("%v", variable.Value)
		result.Type = "unknown"
	}

	return result
}

func oidName(oid string) string {
	names := map[string]string{
		"1.3.6.1.2.1.1.1.0":      "sysDescr",
		"1.3.6.1.2.1.1.2.0":      "sysObjectID",
		"1.3.6.1.2.1.1.3.0":      "sysUpTime",
		"1.3.6.1.2.1.1.4.0":      "sysContact",
		"1.3.6.1.2.1.1.5.0":      "sysName",
		"1.3.6.1.2.1.1.6.0":      "sysLocation",
		"1.3.6.1.2.1.1.7.0":      "sysServices",
		"1.3.6.1.2.1.2.1.0":      "ifNumber",
		"1.3.6.1.2.1.2.2.1.2":    "ifDescr",
		"1.3.6.1.2.1.2.2.1.3":    "ifType",
		"1.3.6.1.2.1.2.2.1.4":    "ifMtu",
		"1.3.6.1.2.1.2.2.1.5":    "ifSpeed",
		"1.3.6.1.2.1.2.2.1.7":    "ifAdminStatus",
		"1.3.6.1.2.1.2.2.1.8":    "ifOperStatus",
		"1.3.6.1.2.1.2.2.1.10":   "ifInOctets",
		"1.3.6.1.2.1.2.2.1.16":   "ifOutOctets",
		"1.3.6.1.2.1.2.2.1.13":   "ifInDiscards",
		"1.3.6.1.2.1.2.2.1.14":   "ifInErrors",
		"1.3.6.1.2.1.2.2.1.19":   "ifOutErrors",
		"1.3.6.1.2.1.2.2.1.20":   "ifOutDiscards",
		"1.3.6.1.2.1.25.3.3.1.2": "hrProcessorLoad",
		"1.3.6.1.2.1.25.2.2.0":   "hrMemorySize",
		"1.3.6.1.2.1.25.2.3.1.5": "hrStorageSize",
		"1.3.6.1.2.1.25.2.3.1.6": "hrStorageUsed",
	}
	if name, ok := names[oid]; ok {
		return name
	}
	parts := strings.Split(oid, ".")
	if len(parts) > 0 {
		return "." + parts[len(parts)-1]
	}
	return oid
}

func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			if b != '\n' && b != '\r' && b != '\t' {
				return false
			}
		}
	}
	return true
}

func emitSNMPResult(probe *Probe, dataChan chan ProbeData, result SNMPPayload) {
	raw, err := json.Marshal(result)
	if err != nil {
		log.Errorf("[snmp] marshal error: %v", err)
		return
	}

	target := ""
	if len(probe.Targets) > 0 {
		target = probe.Targets[0].Target
	}

	dataChan <- ProbeData{
		ProbeID:         probe.ID,
		Type:            ProbeType_SNMP,
		Payload:         raw,
		Target:          target,
		CreatedAt:       time.Now().Add(nettime.GetTimeOffset()),
		SourceInterface: probe.BindInterface,
	}
}
