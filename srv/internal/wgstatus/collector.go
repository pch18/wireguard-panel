package wgstatus

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"wireguard-panel/internal/model"
)

type DumpRunner interface {
	Dump(context.Context) ([]byte, error)
}

type ExecRunner struct {
	Binary string
}

func (runner ExecRunner) Dump(ctx context.Context) ([]byte, error) {
	binary := runner.Binary
	if binary == "" {
		binary = "wg"
	}
	output, err := exec.CommandContext(ctx, binary, "show", "all", "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("run wg show all dump: %w", err)
	}
	return output, nil
}

type Collector struct {
	mu           sync.RWMutex
	runner       DumpRunner
	interval     time.Duration
	activeWindow time.Duration
	available    bool
	message      string
	sampledAt    time.Time
	interfaces   map[string]bool
	peers        map[string]*peerState
}

type peerState struct {
	interfaceName string
	publicKey     string
	endpoint      string
	lastHandshake time.Time
	receivedBytes uint64
	sentBytes     uint64
	receiveRate   float64
	sendRate      float64
	active        bool
	stateSince    time.Time
	sampledAt     time.Time
	history       map[int64]model.TrafficPoint
}

type dumpPeer struct {
	interfaceName string
	publicKey     string
	endpoint      string
	lastHandshake time.Time
	receivedBytes uint64
	sentBytes     uint64
}

func NewCollector(
	runner DumpRunner,
	interval time.Duration,
	activeWindow time.Duration,
) *Collector {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if activeWindow <= 0 {
		activeWindow = 3 * time.Minute
	}
	return &Collector{
		runner:       runner,
		interval:     interval,
		activeWindow: activeWindow,
		interfaces:   make(map[string]bool),
		peers:        make(map[string]*peerState),
	}
}

func (collector *Collector) Start(ctx context.Context) {
	if collector == nil || collector.runner == nil {
		return
	}
	go func() {
		collector.sampleWithTimeout(ctx)
		ticker := time.NewTicker(collector.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				collector.sampleWithTimeout(ctx)
			}
		}
	}()
}

func (collector *Collector) Sample(ctx context.Context, now time.Time) error {
	if collector == nil || collector.runner == nil {
		return fmt.Errorf("wg status collector is not configured")
	}
	output, err := collector.runner.Dump(ctx)
	if err != nil {
		collector.mu.Lock()
		collector.available = false
		collector.message = "无法读取 WireGuard 运行状态；请确认 wg 已安装且进程有权限访问网络接口"
		collector.sampledAt = now
		collector.interfaces = make(map[string]bool)
		collector.mu.Unlock()
		return err
	}
	interfaces, peers, err := parseDump(output)
	if err != nil {
		collector.mu.Lock()
		collector.available = false
		collector.message = "wg 返回了无法解析的运行状态"
		collector.sampledAt = now
		collector.interfaces = make(map[string]bool)
		collector.mu.Unlock()
		return err
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.available = true
	collector.message = ""
	collector.sampledAt = now
	collector.interfaces = interfaces
	for _, sample := range peers {
		collector.ingestLocked(sample, now)
	}
	return nil
}

func (collector *Collector) InterfaceStatus(
	config model.Interface,
	now time.Time,
) model.InterfaceRuntimeStatus {
	result := model.InterfaceRuntimeStatus{
		InterfaceID:   config.ID,
		InterfaceName: strings.TrimSuffix(config.Filename, ".conf"),
		Peers:         make([]model.PeerRuntimeStatus, 0, len(config.Peers)),
	}
	if collector == nil {
		result.Message = "运行状态采集器未启用"
		for _, peer := range config.Peers {
			result.Peers = append(result.Peers, unavailablePeer(peer))
		}
		return result
	}

	collector.mu.RLock()
	defer collector.mu.RUnlock()
	result.CollectorAvailable = collector.available
	result.Message = collector.message
	if !collector.sampledAt.IsZero() {
		sampledAt := collector.sampledAt
		result.SampledAt = &sampledAt
	}
	interfaceRunning := collector.interfaces[result.InterfaceName]
	if collector.available && !interfaceRunning {
		result.Message = "Interface 当前未运行，配置仍可正常编辑"
	}
	for _, peer := range config.Peers {
		state := collector.peers[statusKey(result.InterfaceName, peer.PublicKey)]
		if state == nil {
			result.Peers = append(result.Peers, unavailablePeer(peer))
			continue
		}
		if !collector.available || !interfaceRunning {
			result.Peers = append(
				result.Peers,
				statusFromState(peer, state, now, false, collector.activeWindow),
			)
			continue
		}
		result.Peers = append(
			result.Peers,
			statusFromState(peer, state, now, true, collector.activeWindow),
		)
	}
	return result
}

func statusFromState(
	peer model.Peer,
	state *peerState,
	now time.Time,
	available bool,
	activeWindow time.Duration,
) model.PeerRuntimeStatus {
	active := available &&
		!state.lastHandshake.IsZero() &&
		now.Sub(state.lastHandshake) >= 0 &&
		now.Sub(state.lastHandshake) <= activeWindow
	status := model.PeerRuntimeStatus{
		PeerID:                  peer.ID,
		PublicKey:               peer.PublicKey,
		Available:               available,
		Active:                  active,
		CurrentEndpoint:         state.endpoint,
		ReceivedBytes:           state.receivedBytes,
		SentBytes:               state.sentBytes,
		ReceiveBytesPerSecond:   state.receiveRate,
		SendBytesPerSecond:      state.sendRate,
		ActiveDurationSeconds:   0,
		InactiveDurationSeconds: 0,
		History:                 historyFor(state.history, now),
	}
	if !available {
		status.ReceiveBytesPerSecond = 0
		status.SendBytesPerSecond = 0
	}
	if !state.lastHandshake.IsZero() {
		handshake := state.lastHandshake
		status.LastHandshakeAt = &handshake
	}
	stateSince := state.stateSince
	if !active && state.active {
		stateSince = state.lastHandshake.Add(activeWindow)
		if !available && state.sampledAt.After(stateSince) {
			stateSince = state.sampledAt
		}
	}
	duration := int64(max(0, now.Sub(stateSince).Seconds()))
	if active {
		status.ActiveDurationSeconds = duration
	} else {
		status.InactiveDurationSeconds = duration
	}
	return status
}

func (collector *Collector) sampleWithTimeout(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	_ = collector.Sample(ctx, time.Now().UTC())
}

func (collector *Collector) ingestLocked(sample dumpPeer, now time.Time) {
	key := statusKey(sample.interfaceName, sample.publicKey)
	state := collector.peers[key]
	active := !sample.lastHandshake.IsZero() &&
		now.Sub(sample.lastHandshake) >= 0 &&
		now.Sub(sample.lastHandshake) <= collector.activeWindow
	if state == nil {
		state = &peerState{
			interfaceName: sample.interfaceName,
			publicKey:     sample.publicKey,
			active:        active,
			sampledAt:     now,
			history:       make(map[int64]model.TrafficPoint),
		}
		if active {
			state.stateSince = sample.lastHandshake
		} else if !sample.lastHandshake.IsZero() {
			state.stateSince = sample.lastHandshake.Add(collector.activeWindow)
		} else {
			state.stateSince = now
		}
		collector.peers[key] = state
	} else {
		elapsed := now.Sub(state.sampledAt).Seconds()
		var receivedDelta uint64
		var sentDelta uint64
		if sample.receivedBytes >= state.receivedBytes {
			receivedDelta = sample.receivedBytes - state.receivedBytes
		}
		if sample.sentBytes >= state.sentBytes {
			sentDelta = sample.sentBytes - state.sentBytes
		}
		if elapsed > 0 {
			state.receiveRate = float64(receivedDelta) / elapsed
			state.sendRate = float64(sentDelta) / elapsed
		}
		addHistory(state.history, now, receivedDelta, sentDelta)
		if state.active != active {
			state.active = active
			state.stateSince = now
		}
	}
	state.endpoint = noneToEmpty(sample.endpoint)
	state.lastHandshake = sample.lastHandshake
	state.receivedBytes = sample.receivedBytes
	state.sentBytes = sample.sentBytes
	state.sampledAt = now
	pruneHistory(state.history, now)
}

func parseDump(output []byte) (map[string]bool, []dumpPeer, error) {
	interfaces := make(map[string]bool)
	peers := make([]dumpPeer, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		switch len(fields) {
		case 5:
			interfaces[fields[0]] = true
		case 9:
			handshakeUnix, err := strconv.ParseInt(fields[5], 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("parse latest handshake: %w", err)
			}
			received, err := strconv.ParseUint(fields[6], 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("parse received bytes: %w", err)
			}
			sent, err := strconv.ParseUint(fields[7], 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("parse sent bytes: %w", err)
			}
			var handshake time.Time
			if handshakeUnix > 0 {
				handshake = time.Unix(handshakeUnix, 0).UTC()
			}
			interfaces[fields[0]] = true
			peers = append(peers, dumpPeer{
				interfaceName: fields[0],
				publicKey:     fields[1],
				endpoint:      fields[3],
				lastHandshake: handshake,
				receivedBytes: received,
				sentBytes:     sent,
			})
		default:
			return nil, nil, fmt.Errorf(
				"unexpected wg dump field count %d",
				len(fields),
			)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan wg dump: %w", err)
	}
	return interfaces, peers, nil
}

func addHistory(
	history map[int64]model.TrafficPoint,
	now time.Time,
	received uint64,
	sent uint64,
) {
	minute := now.UTC().Truncate(time.Minute)
	key := minute.Unix()
	point := history[key]
	point.Timestamp = minute
	point.ReceivedBytes += received
	point.SentBytes += sent
	history[key] = point
}

func pruneHistory(history map[int64]model.TrafficPoint, now time.Time) {
	cutoff := now.UTC().Add(-59 * time.Minute).Truncate(time.Minute).Unix()
	for key := range history {
		if key < cutoff {
			delete(history, key)
		}
	}
}

func historyFor(history map[int64]model.TrafficPoint, now time.Time) []model.TrafficPoint {
	current := now.UTC().Truncate(time.Minute)
	points := make([]model.TrafficPoint, 0, 60)
	for offset := 59; offset >= 0; offset-- {
		timestamp := current.Add(-time.Duration(offset) * time.Minute)
		point := history[timestamp.Unix()]
		point.Timestamp = timestamp
		points = append(points, point)
	}
	return points
}

func unavailablePeer(peer model.Peer) model.PeerRuntimeStatus {
	return model.PeerRuntimeStatus{
		PeerID:    peer.ID,
		PublicKey: peer.PublicKey,
		History:   make([]model.TrafficPoint, 0),
	}
}

func statusKey(interfaceName string, publicKey string) string {
	return interfaceName + "\x00" + publicKey
}

func noneToEmpty(value string) string {
	if value == "(none)" {
		return ""
	}
	return value
}
