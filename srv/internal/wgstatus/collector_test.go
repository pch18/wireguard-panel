package wgstatus

import (
	"context"
	"fmt"
	"testing"
	"time"

	"wireguard-panel/internal/model"
)

type sequenceRunner struct {
	outputs [][]byte
	index   int
	err     error
}

func (runner *sequenceRunner) Dump(context.Context) ([]byte, error) {
	if runner.err != nil {
		return nil, runner.err
	}
	index := runner.index
	if index >= len(runner.outputs) {
		index = len(runner.outputs) - 1
	}
	runner.index++
	return runner.outputs[index], nil
}

func TestCollectorCalculatesRatesActivityAndHistory(t *testing.T) {
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
	collector := NewCollector(runner, time.Second, 3*time.Minute)
	if err := collector.Sample(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if err := collector.Sample(context.Background(), start.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	status := collector.InterfaceStatus(model.Interface{
		ID:       0,
		Filename: "wg0.conf",
		Peers: []model.Peer{{
			ID:        "peer-stable-id",
			PublicKey: publicKey,
		}},
	}, start.Add(2*time.Second))
	if !status.CollectorAvailable || len(status.Peers) != 1 {
		t.Fatalf("unexpected interface status: %#v", status)
	}
	peer := status.Peers[0]
	if !peer.Available ||
		!peer.Active ||
		peer.ReceiveBytesPerSecond != 200 ||
		peer.SendBytesPerSecond != 300 ||
		peer.ReceivedBytes != 1400 ||
		peer.SentBytes != 2600 {
		t.Fatalf("unexpected peer status: %#v", peer)
	}
	if len(peer.History) != 60 {
		t.Fatalf("history has %d points", len(peer.History))
	}
	last := peer.History[len(peer.History)-1]
	if last.ReceivedBytes != 400 || last.SentBytes != 600 {
		t.Fatalf("unexpected latest traffic point: %#v", last)
	}

	if err := collector.Sample(
		context.Background(),
		start.Add(4*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	status = collector.InterfaceStatus(
		model.Interface{
			ID:       0,
			Filename: "wg0.conf",
			Peers: []model.Peer{{
				ID:        "peer-stable-id",
				PublicKey: publicKey,
			}},
		},
		start.Add(4*time.Minute),
	)
	if status.Peers[0].Active || status.Peers[0].InactiveDurationSeconds != 0 {
		t.Fatalf("activity transition was not recorded: %#v", status.Peers[0])
	}
}

func TestCollectorReportsUnavailableRunner(t *testing.T) {
	collector := NewCollector(
		&sequenceRunner{err: fmt.Errorf("wg missing")},
		time.Second,
		time.Minute,
	)
	if err := collector.Sample(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("runner error was ignored")
	}
	status := collector.InterfaceStatus(model.Interface{
		Filename: "wg0.conf",
		Peers:    []model.Peer{{ID: "peer", PublicKey: "key"}},
	}, time.Now().UTC())
	if status.CollectorAvailable || status.Message == "" || status.Peers[0].Available {
		t.Fatalf("unavailable collector returned %#v", status)
	}
}
