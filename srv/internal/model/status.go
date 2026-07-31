package model

import "time"

type InterfaceRuntimeStatus struct {
	InterfaceID        int                 `json:"interfaceID"`
	InterfaceName      string              `json:"interfaceName"`
	CollectorAvailable bool                `json:"collectorAvailable"`
	Message            string              `json:"message,omitempty"`
	SampledAt          *time.Time          `json:"sampledAt,omitempty"`
	Peers              []PeerRuntimeStatus `json:"peers"`
}

type PeerRuntimeStatus struct {
	PeerID                  string         `json:"peerID"`
	PublicKey               string         `json:"publicKey"`
	Available               bool           `json:"available"`
	Active                  bool           `json:"active"`
	CurrentEndpoint         string         `json:"currentEndpoint"`
	LastHandshakeAt         *time.Time     `json:"lastHandshakeAt,omitempty"`
	ReceivedBytes           uint64         `json:"receivedBytes"`
	SentBytes               uint64         `json:"sentBytes"`
	ReceiveBytesPerSecond   float64        `json:"receiveBytesPerSecond"`
	SendBytesPerSecond      float64        `json:"sendBytesPerSecond"`
	ActiveDurationSeconds   int64          `json:"activeDurationSeconds"`
	InactiveDurationSeconds int64          `json:"inactiveDurationSeconds"`
	History                 []TrafficPoint `json:"history"`
}

type TrafficPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	ReceivedBytes uint64    `json:"receivedBytes"`
	SentBytes     uint64    `json:"sentBytes"`
}
