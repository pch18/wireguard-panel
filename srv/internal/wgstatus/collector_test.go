package wgstatus

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"wireguard-panel/internal/model"
)

type sequenceSource struct {
	mu        sync.Mutex
	snapshots []Snapshot
	index     int
	err       error
}

func (source *sequenceSource) Snapshot(context.Context) (Snapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.index++
	if source.err != nil {
		return Snapshot{}, source.err
	}
	index := source.index - 1
	if index >= len(source.snapshots) {
		index = len(source.snapshots) - 1
	}
	if index < 0 {
		return Snapshot{}, nil
	}
	return source.snapshots[index], nil
}

func (source *sequenceSource) calls() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.index
}

func deviceSnapshot(name string, peers ...PeerSnapshot) Snapshot {
	return Snapshot{Devices: []DeviceSnapshot{{Name: name, Peers: peers}}}
}

func TestCollectorUsesBackgroundSamplesAndFiveSecondAverageRates(t *testing.T) {
	publicKey := "runtime-peer-public-key"
	start := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	handshake := start.Add(-10 * time.Second)
	peer := func(received, sent uint64) PeerSnapshot {
		return PeerSnapshot{
			PublicKey:     publicKey,
			Endpoint:      "198.51.100.20:51820",
			LastHandshake: handshake,
			ReceivedBytes: received,
			SentBytes:     sent,
		}
	}
	source := &sequenceSource{snapshots: []Snapshot{
		deviceSnapshot("wg0", peer(1000, 2000)),
		deviceSnapshot("wg0", peer(1400, 2600)),
		deviceSnapshot("wg0", peer(2000, 3000)),
		deviceSnapshot("wg0", peer(2000, 3000)),
	}}
	current := start
	collector := NewCollector(source, 3*time.Minute)
	collector.clock = func() time.Time { return current }
	config := model.Interface{
		ID:       "wg0",
		Filename: "wg0.conf",
		Revision: "revision-1",
		Peers:    []model.Peer{{PublicKey: publicKey}},
	}

	if status := collector.InterfaceStatus(context.Background(), config); status.CollectorAvailable {
		t.Fatalf("status read unexpectedly queried the source: %#v", status)
	}
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("first background sample failed: %v", err)
	}
	first := collector.InterfaceStatus(context.Background(), config)
	if source.calls() != 1 || !first.CollectorAvailable || !first.Running {
		t.Fatalf("unexpected first status: calls=%d status=%#v", source.calls(), first)
	}
	if first.ConfigurationRevision != config.Revision ||
		first.Peers[0].ReceiveBytesPerSecond != 0 ||
		first.Peers[0].SendBytesPerSecond != 0 {
		t.Fatalf("unexpected first sample: %#v", first)
	}

	current = start.Add(time.Second)
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("one-second status sample failed: %v", err)
	}
	second := collector.InterfaceStatus(context.Background(), config).Peers[0]
	if second.ReceivedBytes != 1400 || second.SentBytes != 2600 ||
		second.ReceiveBytesPerSecond != 0 || second.SendBytesPerSecond != 0 {
		t.Fatalf("one-second sample incorrectly emitted an interim rate: %#v", second)
	}

	current = start.Add(DefaultTrafficInterval)
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("five-second traffic sample failed: %v", err)
	}
	averaged := collector.InterfaceStatus(context.Background(), config).Peers[0]
	if averaged.ReceiveBytesPerSecond != 200 || averaged.SendBytesPerSecond != 200 {
		t.Fatalf("unexpected five-second average: %#v", averaged)
	}

	current = start.Add(4 * time.Minute)
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("offline status sample failed: %v", err)
	}
	offline := collector.InterfaceStatus(context.Background(), config).Peers[0]
	if offline.Active || offline.InactiveDurationSeconds != 70 {
		t.Fatalf("offline duration was not derived from the handshake: %#v", offline)
	}
}

func TestCollectorAcceptsPeerWithoutEndpoint(t *testing.T) {
	collector := NewCollector(&sequenceSource{snapshots: []Snapshot{
		deviceSnapshot("wg0", PeerSnapshot{PublicKey: "peer-public"}),
	}}, 3*time.Minute)
	now := time.Date(2026, 8, 2, 13, 0, 0, 0, time.UTC)
	config := model.Interface{
		ID:       "wg0",
		Filename: "wg0.conf",
		Peers:    []model.Peer{{PublicKey: "peer-public"}},
	}

	if err := collector.Sample(context.Background(), now); err != nil {
		t.Fatalf("peer without endpoint was rejected: %v", err)
	}
	status := collector.InterfaceStatus(context.Background(), config)
	if !status.CollectorAvailable || !status.Running || !status.Peers[0].Available {
		t.Fatalf("peer without endpoint made status unavailable: %#v", status)
	}
}

func TestCollectorConcurrentStatusReadsNeverQuerySource(t *testing.T) {
	source := &sequenceSource{snapshots: []Snapshot{deviceSnapshot("wg0")}}
	collector := NewCollector(source, 3*time.Minute)
	fixed := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	collector.clock = func() time.Time { return fixed }
	config := model.Interface{ID: "wg0", Filename: "wg0.conf"}
	if err := collector.Sample(context.Background(), fixed); err != nil {
		t.Fatalf("background sample failed: %v", err)
	}

	const requestCount = 12
	var complete sync.WaitGroup
	complete.Add(requestCount)
	for range requestCount {
		go func() {
			defer complete.Done()
			if status := collector.InterfaceStatus(context.Background(), config); !status.CollectorAvailable {
				t.Errorf("snapshot read returned unavailable: %#v", status)
			}
		}()
	}
	complete.Wait()
	if calls := source.calls(); calls != 1 {
		t.Fatalf("%d concurrent reads queried the source: total calls=%d", requestCount, calls)
	}
}

func TestCollectorReportsUnavailableSource(t *testing.T) {
	source := &sequenceSource{err: fmt.Errorf("control unavailable")}
	collector := NewCollector(source, time.Minute)
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	config := model.Interface{
		Filename: "wg0.conf",
		Peers:    []model.Peer{{PublicKey: "key"}},
	}

	if err := collector.Sample(context.Background(), now); err == nil {
		t.Fatal("unavailable source unexpectedly succeeded")
	}
	status := collector.InterfaceStatus(context.Background(), config)
	if status.CollectorAvailable || status.Running || status.Message == "" || status.Peers[0].Available {
		t.Fatalf("unavailable collector returned %#v", status)
	}
	_ = collector.InterfaceStatus(context.Background(), config)
	if source.calls() != 1 {
		t.Fatalf("status read retried the source unexpectedly: calls=%d", source.calls())
	}
	if err := collector.Sample(context.Background(), now.Add(time.Second)); err == nil {
		t.Fatal("second unavailable background sample unexpectedly succeeded")
	}
	if source.calls() != 2 {
		t.Fatalf("next background sample did not retry the source: calls=%d", source.calls())
	}
}

func TestCollectorPublishesSequentialInterfaceStateChanges(t *testing.T) {
	source := &sequenceSource{snapshots: []Snapshot{
		deviceSnapshot("wg0"),
		{},
	}}
	collector := NewCollector(source, time.Minute)
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	config := model.Interface{ID: "wg0", Filename: "wg0.conf"}

	if err := collector.Sample(context.Background(), now); err != nil {
		t.Fatalf("first background sample failed: %v", err)
	}
	if status := collector.InterfaceStatus(context.Background(), config); !status.Running {
		t.Fatalf("first status was not running: %#v", status)
	}
	if err := collector.Sample(context.Background(), now.Add(DefaultStatusInterval)); err != nil {
		t.Fatalf("second background sample failed: %v", err)
	}
	if status := collector.InterfaceStatus(context.Background(), config); status.Running {
		t.Fatalf("second sample did not replace the running state: %#v", status)
	}
}

func TestCollectorSeparatesStatusAndTrafficNotifications(t *testing.T) {
	publicKey := "traffic-peer"
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	peer := func(endpoint string, received, sent uint64) PeerSnapshot {
		return PeerSnapshot{
			PublicKey:     publicKey,
			Endpoint:      endpoint,
			ReceivedBytes: received,
			SentBytes:     sent,
		}
	}
	source := &sequenceSource{snapshots: []Snapshot{
		deviceSnapshot("wg0", peer("", 1000, 2000)),
		deviceSnapshot("wg0", peer("", 1200, 2200)),
		deviceSnapshot("wg0", peer("198.51.100.20:51820", 1400, 2400)),
		deviceSnapshot("wg0", peer("198.51.100.20:51820", 2000, 3000)),
	}}
	collector := NewCollector(source, time.Minute)
	updates, unsubscribe := collector.Subscribe()
	defer unsubscribe()

	if err := collector.Sample(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	expectNotification(t, updates.Status, "initial status")
	expectNoNotification(t, updates.Traffic, "initial traffic")

	if err := collector.Sample(context.Background(), start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	expectNoNotification(t, updates.Status, "counter-only status")
	expectNoNotification(t, updates.Traffic, "one-second traffic")

	if err := collector.Sample(context.Background(), start.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	expectNotification(t, updates.Status, "endpoint change")
	expectNoNotification(t, updates.Traffic, "pre-window traffic")

	if err := collector.Sample(context.Background(), start.Add(DefaultTrafficInterval)); err != nil {
		t.Fatal(err)
	}
	expectNoNotification(t, updates.Status, "unchanged status")
	expectNotification(t, updates.Traffic, "five-second traffic")
	traffic, _ := collector.TrafficHistory("wg0", time.Time{}, []string{publicKey})
	if len(traffic) != 1 ||
		traffic[0].ReceiveBytesPerSecond != 200 ||
		traffic[0].SendBytesPerSecond != 200 {
		t.Fatalf("unexpected five-second traffic point: %#v", traffic)
	}
}

func TestCollectorRetainsOneHourTrafficHistory(t *testing.T) {
	publicKey := "traffic-peer"
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	peer := func(received, sent uint64) PeerSnapshot {
		return PeerSnapshot{PublicKey: publicKey, ReceivedBytes: received, SentBytes: sent}
	}
	collector := NewCollector(&sequenceSource{snapshots: []Snapshot{
		deviceSnapshot("wg0", peer(1000, 2000)),
		deviceSnapshot("wg0", peer(1200, 2400)),
		deviceSnapshot("wg0", peer(1800, 3000)),
	}}, time.Minute)
	collector.historyWindow = 30 * time.Second

	for _, offset := range []time.Duration{0, 20 * time.Second, 40 * time.Second} {
		if err := collector.Sample(context.Background(), start.Add(offset)); err != nil {
			t.Fatalf("sample at %s failed: %v", offset, err)
		}
	}
	interfaceTraffic, peerTraffic := collector.TrafficHistory(
		"wg0",
		time.Time{},
		[]string{publicKey},
	)
	if len(interfaceTraffic) != 2 || len(peerTraffic[publicKey]) != 2 {
		t.Fatalf("history retention mismatch: Interface=%#v Peer=%#v", interfaceTraffic, peerTraffic[publicKey])
	}
	latest := interfaceTraffic[1]
	if latest.ReceiveBytesPerSecond != 30 || latest.SendBytesPerSecond != 30 {
		t.Fatalf("unexpected Interface aggregate point: %#v", latest)
	}
	after, _ := collector.TrafficHistory(
		"wg0",
		start.Add(20*time.Second),
		[]string{publicKey},
	)
	if len(after) != 1 {
		t.Fatalf("exclusive history cursor returned %#v", after)
	}
	_, emptyPeerTraffic := collector.TrafficHistory(
		"wg0",
		time.Time{},
		[]string{"new-peer-without-history"},
	)
	if emptyPeerTraffic["new-peer-without-history"] == nil {
		t.Fatal("Peer without traffic history returned a nil slice")
	}
}

func expectNotification(t *testing.T, updates <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-updates:
	default:
		t.Fatalf("missing %s notification", label)
	}
}

func expectNoNotification(t *testing.T, updates <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-updates:
		t.Fatalf("unexpected %s notification", label)
	default:
	}
}
