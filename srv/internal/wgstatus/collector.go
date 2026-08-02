package wgstatus

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wireguard-panel/internal/model"
)

const (
	sampleTimeout         = 3 * time.Second
	DefaultSampleInterval = 3 * time.Second
	DefaultHistoryWindow  = time.Hour
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
	mu            sync.RWMutex
	runner        DumpRunner
	activeWindow  time.Duration
	historyWindow time.Duration
	available     bool
	message       string
	sampledAt     time.Time
	interfaces    map[string]dumpInterface
	peers         map[string]*peerState
	histories     map[string]*interfaceHistory

	subscribersMu    sync.Mutex
	subscribers      map[uint64]chan struct{}
	nextSubscriberID uint64
	clock            func() time.Time
}

type interfaceHistory struct {
	traffic []model.TrafficPoint
	peers   map[string][]model.TrafficPoint
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
}

type dumpPeer struct {
	interfaceName string
	publicKey     string
	endpoint      string
	lastHandshake time.Time
	receivedBytes uint64
	sentBytes     uint64
}

type dumpInterface struct{}

func NewCollector(
	runner DumpRunner,
	activeWindow time.Duration,
) *Collector {
	if activeWindow <= 0 {
		activeWindow = 3 * time.Minute
	}
	return &Collector{
		runner:        runner,
		activeWindow:  activeWindow,
		historyWindow: DefaultHistoryWindow,
		interfaces:    make(map[string]dumpInterface),
		peers:         make(map[string]*peerState),
		histories:     make(map[string]*interfaceHistory),
		subscribers:   make(map[uint64]chan struct{}),
		clock:         time.Now,
	}
}

// Run is the sole periodic WireGuard sampling loop. HTTP status and SSE
// handlers only read the in-memory snapshot populated here.
func (collector *Collector) Run(ctx context.Context) {
	if collector == nil || collector.runner == nil {
		return
	}
	collector.sampleWithTimeout(ctx)
	ticker := time.NewTicker(DefaultSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collector.sampleWithTimeout(ctx)
		}
	}
}

func (collector *Collector) sampleWithTimeout(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, sampleTimeout)
	defer cancel()
	_ = collector.Sample(ctx, collector.now())
}

// InterfaceStatus only reads the latest background sample and never executes
// wg itself.
func (collector *Collector) InterfaceStatus(
	_ context.Context,
	config model.Interface,
) model.InterfaceRuntimeStatus {
	if collector == nil || collector.runner == nil {
		return unavailableInterface(config, "运行状态采集器未启用")
	}
	return collector.interfaceStatus(config, collector.now())
}

func (collector *Collector) now() time.Time {
	return collector.clock().UTC()
}

func (collector *Collector) Sample(ctx context.Context, now time.Time) error {
	if collector == nil || collector.runner == nil {
		return fmt.Errorf("wg status collector is not configured")
	}
	output, err := collector.runner.Dump(ctx)
	if err != nil {
		collector.markUnavailable(now, "无法读取 WireGuard 运行状态；请确认 wg 已安装且进程有权限访问网络接口")
		return err
	}
	interfaces, peers, err := parseDump(output)
	if err != nil {
		collector.markUnavailable(now, "wg 返回了无法解析的运行状态")
		return err
	}

	collector.mu.Lock()
	collector.available = true
	collector.message = ""
	collector.sampledAt = now
	collector.interfaces = interfaces
	seen := make(map[string]struct{}, len(peers))
	for _, sample := range peers {
		key := statusKey(sample.interfaceName, sample.publicKey)
		seen[key] = struct{}{}
		collector.ingestLocked(sample, now)
	}
	collector.recordTrafficLocked(interfaces, peers, now)
	for key := range collector.peers {
		if _, ok := seen[key]; !ok {
			delete(collector.peers, key)
		}
	}
	collector.pruneHistoriesLocked(now.Add(-collector.historyWindow))
	collector.mu.Unlock()
	collector.notifySubscribers()
	return nil
}

func (collector *Collector) markUnavailable(now time.Time, message string) {
	collector.mu.Lock()
	collector.available = false
	collector.message = message
	collector.sampledAt = now
	collector.interfaces = make(map[string]dumpInterface)
	collector.pruneHistoriesLocked(now.Add(-collector.historyWindow))
	collector.mu.Unlock()
	collector.notifySubscribers()
}

func (collector *Collector) recordTrafficLocked(
	interfaces map[string]dumpInterface,
	peers []dumpPeer,
	now time.Time,
) {
	interfacePoints := make(map[string]model.TrafficPoint, len(interfaces))
	seenPeers := make(map[string]map[string]struct{}, len(interfaces))
	for interfaceName := range interfaces {
		interfacePoints[interfaceName] = model.TrafficPoint{SampledAt: now}
		seenPeers[interfaceName] = make(map[string]struct{})
	}
	for _, sample := range peers {
		state := collector.peers[statusKey(sample.interfaceName, sample.publicKey)]
		if state == nil {
			continue
		}
		point := model.TrafficPoint{
			SampledAt:             now,
			ReceiveBytesPerSecond: state.receiveRate,
			SendBytesPerSecond:    state.sendRate,
		}
		history := collector.historyLocked(sample.interfaceName)
		history.peers[sample.publicKey] = appendTrafficPoint(
			history.peers[sample.publicKey],
			point,
		)
		seenPeers[sample.interfaceName][sample.publicKey] = struct{}{}
		total := interfacePoints[sample.interfaceName]
		total.ReceiveBytesPerSecond += point.ReceiveBytesPerSecond
		total.SendBytesPerSecond += point.SendBytesPerSecond
		interfacePoints[sample.interfaceName] = total
	}
	for interfaceName, total := range interfacePoints {
		history := collector.historyLocked(interfaceName)
		history.traffic = appendTrafficPoint(history.traffic, total)
		for publicKey, points := range history.peers {
			if _, ok := seenPeers[interfaceName][publicKey]; ok {
				continue
			}
			history.peers[publicKey] = appendTrafficPoint(
				points,
				model.TrafficPoint{SampledAt: now},
			)
		}
	}
}

func (collector *Collector) historyLocked(interfaceName string) *interfaceHistory {
	history := collector.histories[interfaceName]
	if history == nil {
		history = &interfaceHistory{peers: make(map[string][]model.TrafficPoint)}
		collector.histories[interfaceName] = history
	}
	return history
}

func appendTrafficPoint(
	points []model.TrafficPoint,
	point model.TrafficPoint,
) []model.TrafficPoint {
	if len(points) == 0 {
		return append(points, point)
	}
	last := len(points) - 1
	if point.SampledAt.Equal(points[last].SampledAt) {
		points[last] = point
		return points
	}
	if point.SampledAt.Before(points[last].SampledAt) {
		return points
	}
	return append(points, point)
}

func (collector *Collector) pruneHistoriesLocked(cutoff time.Time) {
	for interfaceName, history := range collector.histories {
		history.traffic = pruneTrafficPoints(history.traffic, cutoff)
		for publicKey, points := range history.peers {
			points = pruneTrafficPoints(points, cutoff)
			if len(points) == 0 {
				delete(history.peers, publicKey)
				continue
			}
			history.peers[publicKey] = points
		}
		if len(history.traffic) == 0 && len(history.peers) == 0 {
			delete(collector.histories, interfaceName)
		}
	}
}

func pruneTrafficPoints(points []model.TrafficPoint, cutoff time.Time) []model.TrafficPoint {
	first := sort.Search(len(points), func(index int) bool {
		return !points[index].SampledAt.Before(cutoff)
	})
	if first == 0 {
		return points
	}
	copy(points, points[first:])
	return points[:len(points)-first]
}

func (collector *Collector) TrafficHistory(
	interfaceName string,
	after time.Time,
	peerPublicKeys []string,
) ([]model.TrafficPoint, map[string][]model.TrafficPoint) {
	traffic := []model.TrafficPoint{}
	peerTraffic := make(map[string][]model.TrafficPoint, len(peerPublicKeys))
	if collector == nil {
		return traffic, peerTraffic
	}
	collector.mu.RLock()
	defer collector.mu.RUnlock()
	history := collector.histories[interfaceName]
	if history == nil {
		return traffic, peerTraffic
	}
	traffic = trafficPointsAfter(history.traffic, after)
	for _, publicKey := range peerPublicKeys {
		peerTraffic[publicKey] = trafficPointsAfter(history.peers[publicKey], after)
	}
	return traffic, peerTraffic
}

func trafficPointsAfter(points []model.TrafficPoint, after time.Time) []model.TrafficPoint {
	first := 0
	if !after.IsZero() {
		first = sort.Search(len(points), func(index int) bool {
			return points[index].SampledAt.After(after)
		})
	}
	return append([]model.TrafficPoint{}, points[first:]...)
}

func (collector *Collector) Subscribe() (<-chan struct{}, func()) {
	if collector == nil {
		return nil, func() {}
	}
	collector.subscribersMu.Lock()
	collector.nextSubscriberID++
	id := collector.nextSubscriberID
	updates := make(chan struct{}, 1)
	collector.subscribers[id] = updates
	collector.subscribersMu.Unlock()
	return updates, func() {
		collector.subscribersMu.Lock()
		delete(collector.subscribers, id)
		collector.subscribersMu.Unlock()
	}
}

func (collector *Collector) notifySubscribers() {
	if collector == nil {
		return
	}
	collector.subscribersMu.Lock()
	defer collector.subscribersMu.Unlock()
	for _, subscriber := range collector.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
}

func (collector *Collector) interfaceStatus(
	config model.Interface,
	now time.Time,
) model.InterfaceRuntimeStatus {
	result := model.InterfaceRuntimeStatus{
		InterfaceID:           config.ID,
		InterfaceName:         strings.TrimSuffix(config.Filename, ".conf"),
		ConfigurationRevision: config.Revision,
		Peers:                 make([]model.PeerRuntimeStatus, 0, len(config.Peers)),
	}
	collector.mu.RLock()
	defer collector.mu.RUnlock()
	result.CollectorAvailable = collector.available
	result.Message = collector.message
	if collector.sampledAt.IsZero() && result.Message == "" {
		result.Message = "运行状态采样尚未完成"
	}
	if !collector.sampledAt.IsZero() {
		sampledAt := collector.sampledAt
		result.SampledAt = &sampledAt
	}
	_, interfaceRunning := collector.interfaces[result.InterfaceName]
	result.Running = collector.available && interfaceRunning
	if collector.available && !interfaceRunning {
		result.Message = ""
	}
	for _, peer := range config.Peers {
		state := collector.peers[statusKey(result.InterfaceName, peer.PublicKey)]
		if state == nil {
			result.Peers = append(result.Peers, unavailablePeer(peer))
			continue
		}
		result.Peers = append(
			result.Peers,
			statusFromState(
				peer,
				state,
				now,
				collector.available && interfaceRunning,
				collector.activeWindow,
			),
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
		PublicKey:             peer.PublicKey,
		Available:             available,
		Active:                active,
		CurrentEndpoint:       state.endpoint,
		ReceivedBytes:         state.receivedBytes,
		SentBytes:             state.sentBytes,
		ReceiveBytesPerSecond: state.receiveRate,
		SendBytesPerSecond:    state.sendRate,
	}
	if !available {
		status.ReceiveBytesPerSecond = 0
		status.SendBytesPerSecond = 0
	}
	if !state.lastHandshake.IsZero() {
		handshake := state.lastHandshake
		status.LastHandshakeAt = &handshake
	}
	duration := int64(max(0, now.Sub(state.stateSince).Seconds()))
	if active {
		status.ActiveDurationSeconds = duration
	} else {
		status.InactiveDurationSeconds = duration
	}
	return status
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
			stateSince:    stateStart(sample.lastHandshake, now, active, collector.activeWindow),
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
		if state.active != active {
			state.active = active
			state.stateSince = stateStart(
				sample.lastHandshake,
				now,
				active,
				collector.activeWindow,
			)
		}
	}
	state.endpoint = noneToEmpty(sample.endpoint)
	state.lastHandshake = sample.lastHandshake
	state.receivedBytes = sample.receivedBytes
	state.sentBytes = sample.sentBytes
	state.sampledAt = now
}

func stateStart(
	lastHandshake time.Time,
	now time.Time,
	active bool,
	activeWindow time.Duration,
) time.Time {
	if lastHandshake.IsZero() {
		return now
	}
	if active {
		return lastHandshake
	}
	return lastHandshake.Add(activeWindow)
}

func parseDump(output []byte) (map[string]dumpInterface, []dumpPeer, error) {
	interfaces := make(map[string]dumpInterface)
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
			interfaces[fields[0]] = dumpInterface{}
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
			peers = append(peers, dumpPeer{
				interfaceName: fields[0],
				publicKey:     fields[1],
				endpoint:      fields[3],
				lastHandshake: handshake,
				receivedBytes: received,
				sentBytes:     sent,
			})
			if _, err := strconv.ParseUint(fields[8], 10, 16); err != nil {
				return nil, nil, fmt.Errorf("parse persistent keepalive: %w", err)
			}
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

func unavailableInterface(config model.Interface, message string) model.InterfaceRuntimeStatus {
	result := model.InterfaceRuntimeStatus{
		InterfaceID:           config.ID,
		InterfaceName:         strings.TrimSuffix(config.Filename, ".conf"),
		ConfigurationRevision: config.Revision,
		Message:               message,
		Peers:                 make([]model.PeerRuntimeStatus, 0, len(config.Peers)),
	}
	for _, peer := range config.Peers {
		result.Peers = append(result.Peers, unavailablePeer(peer))
	}
	return result
}

func unavailablePeer(peer model.Peer) model.PeerRuntimeStatus {
	return model.PeerRuntimeStatus{
		PublicKey: peer.PublicKey,
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
