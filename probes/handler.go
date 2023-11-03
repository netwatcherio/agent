package probes

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type Probe struct {
	Type          ProbeType          `json:"type"bson:"type"`
	ID            primitive.ObjectID `json:"id"bson:"_id"`
	Agent         primitive.ObjectID `json:"agent"bson:"agent"`
	CreatedAt     time.Time          `bson:"createdAt"json:"createdAt"`
	UpdatedAt     time.Time          `bson:"updatedAt"json:"updatedAt"`
	Notifications bool               `json:"notifications"bson:"notifications"` // notifications will be emailed to anyone who has permissions on their account / associated with the site
	Config        ProbeConfig        `bson:"config"json:"config"`
}

type ProbeType string

const (
	ProbeType_RPERF       ProbeType = "RPERF"
	ProbeType_MTR         ProbeType = "MTR"
	ProbeType_PING        ProbeType = "PING"
	ProbeType_SPEEDTEST   ProbeType = "SPEEDTEST"
	ProbeType_NETWORKINFO ProbeType = "NETINFO"
)

type ProbeConfig struct {
	Target   string    `json:"target" bson:"target"`
	Duration int       `json:"duration" bson:"duration"`
	Count    int       `json:"count" bson:"count"`
	Interval int       `json:"interval" bson:"interval"`
	Server   bool      `bson:"server" json:"server"`
	Pending  time.Time `json:"pending" bson:"pending"` // timestamp of when it was made pending / invalidate it after 10 minutes or so?
}

type ProbeData struct {
	ID        primitive.ObjectID `json:"id"bson:"_id"`
	ProbeID   primitive.ObjectID `json:"probe"bson:"probe"`
	Triggered bool               `json:"triggered"bson:"triggered"`
	CreatedAt time.Time          `bson:"createdAt"json:"createdAt"`
	UpdatedAt time.Time          `bson:"updatedAt"json:"updatedAt"`
	Data      interface{}        `json:"data,omitempty"bson:"data,omitempty"`
}
