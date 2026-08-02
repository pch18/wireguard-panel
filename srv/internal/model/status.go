package model

import "time"

type InterfaceRuntimeStatus struct {
	InterfaceID           string              `json:"interfaceID"`
	InterfaceName         string              `json:"interfaceName"`
	ConfigurationRevision string              `json:"configurationRevision"`
	RuntimeControllable   bool                `json:"runtimeControllable"`
	RuntimeStateAvailable bool                `json:"runtimeStateAvailable"`
	Running               bool                `json:"running"`
	CollectorAvailable    bool                `json:"collectorAvailable"`
	Message               string              `json:"message,omitempty"`
	SampledAt             *time.Time          `json:"sampledAt,omitempty"`
	Peers                 []PeerRuntimeStatus `json:"peers"`
}

type PeerRuntimeStatus struct {
	PublicKey               string     `json:"publicKey"`
	Available               bool       `json:"available"`
	Active                  bool       `json:"active"`
	CurrentEndpoint         string     `json:"currentEndpoint"`
	LastHandshakeAt         *time.Time `json:"lastHandshakeAt,omitempty"`
	ReceivedBytes           uint64     `json:"receivedBytes"`
	SentBytes               uint64     `json:"sentBytes"`
	ReceiveBytesPerSecond   float64    `json:"receiveBytesPerSecond"`
	SendBytesPerSecond      float64    `json:"sendBytesPerSecond"`
	ActiveDurationSeconds   int64      `json:"activeDurationSeconds"`
	InactiveDurationSeconds int64      `json:"inactiveDurationSeconds"`
}

type TrafficPoint struct {
	SampledAt             time.Time `json:"sampledAt"`
	ReceiveBytesPerSecond float64   `json:"receiveBytesPerSecond"`
	SendBytesPerSecond    float64   `json:"sendBytesPerSecond"`
}

type InterfaceTrafficEvent struct {
	Kind             string                    `json:"kind"`
	Status           InterfaceRuntimeStatus    `json:"status"`
	InterfaceTraffic []TrafficPoint            `json:"interfaceTraffic"`
	PeerTraffic      map[string][]TrafficPoint `json:"peerTraffic"`
}
