package wgstatus

import (
	"context"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
)

type SnapshotSource interface {
	Snapshot(context.Context) (Snapshot, error)
}

type Snapshot struct {
	Devices []DeviceSnapshot
}

type DeviceSnapshot struct {
	Name  string
	Peers []PeerSnapshot
}

type PeerSnapshot struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	ReceivedBytes uint64
	SentBytes     uint64
}

type WGCtrlSource struct {
	client *wgctrl.Client
}

func NewWGCtrlSource() (*WGCtrlSource, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open WireGuard control client: %w", err)
	}
	return &WGCtrlSource{client: client}, nil
}

func (source *WGCtrlSource) Close() error {
	if source == nil || source.client == nil {
		return nil
	}
	return source.client.Close()
}

func (source *WGCtrlSource) Snapshot(ctx context.Context) (Snapshot, error) {
	if source == nil || source.client == nil {
		return Snapshot{}, fmt.Errorf("WireGuard control client is not configured")
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	devices, err := source.client.Devices()
	if err != nil {
		return Snapshot{}, fmt.Errorf("read WireGuard devices: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}

	snapshot := Snapshot{Devices: make([]DeviceSnapshot, 0, len(devices))}
	for _, device := range devices {
		deviceSnapshot := DeviceSnapshot{
			Name:  device.Name,
			Peers: make([]PeerSnapshot, 0, len(device.Peers)),
		}
		for _, peer := range device.Peers {
			endpoint := ""
			if peer.Endpoint != nil {
				endpoint = peer.Endpoint.String()
			}
			receivedBytes := uint64(0)
			if peer.ReceiveBytes > 0 {
				receivedBytes = uint64(peer.ReceiveBytes)
			}
			sentBytes := uint64(0)
			if peer.TransmitBytes > 0 {
				sentBytes = uint64(peer.TransmitBytes)
			}
			lastHandshake := peer.LastHandshakeTime
			if !lastHandshake.IsZero() {
				lastHandshake = lastHandshake.UTC()
			}
			deviceSnapshot.Peers = append(deviceSnapshot.Peers, PeerSnapshot{
				PublicKey:     peer.PublicKey.String(),
				Endpoint:      endpoint,
				LastHandshake: lastHandshake,
				ReceivedBytes: receivedBytes,
				SentBytes:     sentBytes,
			})
		}
		snapshot.Devices = append(snapshot.Devices, deviceSnapshot)
	}
	return snapshot, nil
}
