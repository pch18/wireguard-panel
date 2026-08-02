package wgstatus

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wireguard-panel/internal/model"
)

type sequenceRunner struct {
	mu      sync.Mutex
	outputs [][]byte
	index   int
	err     error
}

func (runner *sequenceRunner) Dump(context.Context) ([]byte, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.index++
	if runner.err != nil {
		return nil, runner.err
	}
	index := runner.index - 1
	if index >= len(runner.outputs) {
		index = len(runner.outputs) - 1
	}
	return runner.outputs[index], nil
}

func (runner *sequenceRunner) calls() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.index
}

func TestCollectorUsesBackgroundSamplesAndCalculatesRates(t *testing.T) {
	publicKey := "runtime-peer-public-key"
	start := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	handshake := start.Add(-10 * time.Second).Unix()
	runner := &sequenceRunner{outputs: [][]byte{
		[]byte(fmt.Sprintf(
			"wg0\tprivate\tpublic\t51820\toff\n"+
				"wg0\t%s\t(none)\t198.51.100.20:51820\t10.0.0.2/32\t%d\t1000\t2000\t25\n",
			publicKey,
			handshake,
		)),
		[]byte(fmt.Sprintf(
			"wg0\tprivate\tpublic\t51820\toff\n"+
				"wg0\t%s\t(none)\t198.51.100.20:51820\t10.0.0.2/32\t%d\t1400\t2600\t25\n",
			publicKey,
			handshake,
		)),
	}}
	current := start
	collector := NewCollector(runner, 3*time.Minute)
	collector.clock = func() time.Time { return current }
	config := model.Interface{
		ID:       "wg0",
		Filename: "wg0.conf",
		Revision: "revision-1",
		Peers: []model.Peer{{
			PublicKey: publicKey,
		}},
	}

	if runner.calls() != 0 {
		t.Fatal("collector executed wg before a status request")
	}
	if status := collector.InterfaceStatus(context.Background(), config); status.CollectorAvailable {
		t.Fatalf("status read unexpectedly sampled wg: %#v", status)
	}
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("first background sample failed: %v", err)
	}
	first := collector.InterfaceStatus(context.Background(), config)
	if runner.calls() != 1 || !first.CollectorAvailable || !first.Running {
		t.Fatalf("first request did not sample exactly once: calls=%d status=%#v", runner.calls(), first)
	}
	if first.ConfigurationRevision != config.Revision {
		t.Fatalf("status revision %q does not match config %q", first.ConfigurationRevision, config.Revision)
	}
	if first.Peers[0].ReceiveBytesPerSecond != 0 || first.Peers[0].SendBytesPerSecond != 0 {
		t.Fatalf("first sample unexpectedly reported a rate: %#v", first.Peers[0])
	}

	current = start.Add(500 * time.Millisecond)
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("second background sample failed: %v", err)
	}
	second := collector.InterfaceStatus(context.Background(), config)
	if runner.calls() != 2 {
		t.Fatalf("second request did not read wg again: calls=%d", runner.calls())
	}
	peer := second.Peers[0]
	if !peer.Available ||
		!peer.Active ||
		peer.ReceiveBytesPerSecond != 800 ||
		peer.SendBytesPerSecond != 1200 ||
		peer.ReceivedBytes != 1400 ||
		peer.SentBytes != 2600 {
		t.Fatalf("unexpected peer status: %#v", peer)
	}

	current = start.Add(4 * time.Minute)
	if err := collector.Sample(context.Background(), current); err != nil {
		t.Fatalf("third background sample failed: %v", err)
	}
	offline := collector.InterfaceStatus(context.Background(), config).Peers[0]
	if runner.calls() != 3 {
		t.Fatalf("third request did not read wg again: calls=%d", runner.calls())
	}
	if offline.Active || offline.InactiveDurationSeconds != 70 {
		t.Fatalf("sparse request did not derive offline duration: %#v", offline)
	}
}

func TestCollectorAcceptsDisabledPersistentKeepalive(t *testing.T) {
	collector := NewCollector(&sequenceRunner{outputs: [][]byte{
		[]byte(
			"wg0\tprivate\tpublic\t51820\toff\n" +
				"wg0\tpeer-public\t(none)\t(none)\t10.0.0.2/32\t0\t0\t0\toff\n",
		),
	}}, 3*time.Minute)
	now := time.Date(2026, 8, 2, 13, 0, 0, 0, time.UTC)
	collector.clock = func() time.Time { return now }
	config := model.Interface{
		ID:       "wg0",
		Filename: "wg0.conf",
		Peers:    []model.Peer{{PublicKey: "peer-public"}},
	}

	if err := collector.Sample(context.Background(), now); err != nil {
		t.Fatalf("disabled PersistentKeepalive rejected: %v", err)
	}
	status := collector.InterfaceStatus(context.Background(), config)
	if !status.CollectorAvailable || !status.Running || !status.Peers[0].Available {
		t.Fatalf("disabled PersistentKeepalive made status unavailable: %#v", status)
	}
}

type blockingRunner struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
	output  []byte
}

func (runner *blockingRunner) Dump(ctx context.Context) ([]byte, error) {
	runner.calls.Add(1)
	select {
	case runner.started <- struct{}{}:
	default:
	}
	select {
	case <-runner.release:
		return runner.output, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestCollectorConcurrentStatusReadsNeverExecuteWG(t *testing.T) {
	runner := &sequenceRunner{outputs: [][]byte{
		[]byte("wg0\tprivate\tpublic\t51820\toff\n"),
	}}
	collector := NewCollector(runner, 3*time.Minute)
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
			status := collector.InterfaceStatus(context.Background(), config)
			if !status.CollectorAvailable {
				t.Errorf("snapshot read returned unavailable: %#v", status)
			}
		}()
	}
	complete.Wait()
	if calls := runner.calls(); calls != 1 {
		t.Fatalf("%d concurrent status reads executed wg: total calls=%d", requestCount, calls)
	}
}

func TestCollectorReportsUnavailableRunnerOnDemand(t *testing.T) {
	runner := &sequenceRunner{err: fmt.Errorf("wg missing")}
	collector := NewCollector(runner, time.Minute)
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	collector.clock = func() time.Time { return now }
	config := model.Interface{
		Filename: "wg0.conf",
		Peers:    []model.Peer{{PublicKey: "key"}},
	}

	if err := collector.Sample(context.Background(), now); err == nil {
		t.Fatal("unavailable background sample unexpectedly succeeded")
	}
	status := collector.InterfaceStatus(context.Background(), config)
	if status.CollectorAvailable || status.Running || status.Message == "" || status.Peers[0].Available {
		t.Fatalf("unavailable collector returned %#v", status)
	}
	if runner.calls() != 1 {
		t.Fatalf("failed request executed wg %d times", runner.calls())
	}
	now = now.Add(500 * time.Millisecond)
	_ = collector.InterfaceStatus(context.Background(), config)
	if runner.calls() != 1 {
		t.Fatalf("status read retried wg unexpectedly: calls=%d", runner.calls())
	}
	if err := collector.Sample(context.Background(), now); err == nil {
		t.Fatal("second unavailable background sample unexpectedly succeeded")
	}
	if runner.calls() != 2 {
		t.Fatalf("next background sample did not retry wg: calls=%d", runner.calls())
	}
}

func TestCollectorPublishesEverySequentialBackgroundSample(t *testing.T) {
	runner := &sequenceRunner{outputs: [][]byte{
		[]byte("wg0\tprivate\tpublic\t51820\toff\n"),
		[]byte(""),
	}}
	collector := NewCollector(runner, time.Minute)
	now := time.Date(2026, 7, 31, 10, 0, 0, 0, time.UTC)
	collector.clock = func() time.Time { return now }
	config := model.Interface{ID: "wg0", Filename: "wg0.conf"}

	if err := collector.Sample(context.Background(), now); err != nil {
		t.Fatalf("first background sample failed: %v", err)
	}
	if status := collector.InterfaceStatus(context.Background(), config); !status.Running {
		t.Fatalf("first status was not running: %#v", status)
	}
	if err := collector.Sample(context.Background(), now.Add(3*time.Second)); err != nil {
		t.Fatalf("second background sample failed: %v", err)
	}
	if status := collector.InterfaceStatus(context.Background(), config); status.Running {
		t.Fatalf("second sample did not replace the running state: %#v", status)
	}
	if runner.calls() != 2 {
		t.Fatalf("two sequential requests executed wg %d times", runner.calls())
	}
}

func TestCollectorRetainsTrafficHistoryAndNotifiesSubscribers(t *testing.T) {
	publicKey := "traffic-peer"
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	runner := &sequenceRunner{outputs: [][]byte{
		[]byte(fmt.Sprintf(
			"wg0\tprivate\tpublic\t51820\toff\n"+
				"wg0\t%s\t(none)\t(none)\t10.0.0.2/32\t0\t1000\t2000\t0\n",
			publicKey,
		)),
		[]byte(fmt.Sprintf(
			"wg0\tprivate\tpublic\t51820\toff\n"+
				"wg0\t%s\t(none)\t(none)\t10.0.0.2/32\t0\t1200\t2400\t0\n",
			publicKey,
		)),
		[]byte(fmt.Sprintf(
			"wg0\tprivate\tpublic\t51820\toff\n"+
				"wg0\t%s\t(none)\t(none)\t10.0.0.2/32\t0\t1800\t3000\t0\n",
			publicKey,
		)),
	}}
	collector := NewCollector(runner, time.Minute)
	collector.historyWindow = 30 * time.Second
	updates, unsubscribe := collector.Subscribe()
	defer unsubscribe()

	for _, offset := range []time.Duration{0, 20 * time.Second, 40 * time.Second} {
		if err := collector.Sample(context.Background(), start.Add(offset)); err != nil {
			t.Fatalf("sample at %s failed: %v", offset, err)
		}
	}
	select {
	case <-updates:
	default:
		t.Fatal("background sample did not notify the subscriber")
	}

	interfaceTraffic, peerTraffic := collector.TrafficHistory(
		"wg0",
		time.Time{},
		[]string{publicKey},
	)
	if len(interfaceTraffic) != 2 || len(peerTraffic[publicKey]) != 2 {
		t.Fatalf(
			"history retention mismatch: Interface=%#v Peer=%#v",
			interfaceTraffic,
			peerTraffic[publicKey],
		)
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
