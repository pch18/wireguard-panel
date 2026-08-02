package wgstatus

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"wireguard-panel/internal/model"
)

const (
	sampleTimeout          = 3 * time.Second
	DefaultStatusInterval  = time.Second
	DefaultTrafficInterval = 5 * time.Second
	DefaultHistoryWindow   = time.Hour
)

type Collector struct {
	mu               sync.RWMutex
	source           SnapshotSource
	activeWindow     time.Duration
	historyWindow    time.Duration
	available        bool
	message          string
	sampledAt        time.Time
	interfaces       map[string]struct{}
	peers            map[string]*peerState
	histories        map[string]*interfaceHistory
	trafficBaselines map[string]trafficBaseline
	lastTrafficAt    time.Time

	subscribersMu    sync.Mutex
	subscribers      map[uint64]*collectorSubscriber
	nextSubscriberID uint64
	clock            func() time.Time
}

type interfaceHistory struct {
	traffic []model.TrafficPoint
	peers   map[string][]model.TrafficPoint
}

type peerState struct {
	endpoint      string
	lastHandshake time.Time
	receivedBytes uint64
	sentBytes     uint64
	receiveRate   float64
	sendRate      float64
	active        bool
	stateSince    time.Time
}

type trafficBaseline struct {
	receivedBytes uint64
	sentBytes     uint64
	sampledAt     time.Time
}

type collectorSubscriber struct {
	status  chan struct{}
	traffic chan struct{}
}

type Subscription struct {
	Status  <-chan struct{}
	Traffic <-chan struct{}
}

type peerSample struct {
	interfaceName string
	publicKey     string
	endpoint      string
	lastHandshake time.Time
	receivedBytes uint64
	sentBytes     uint64
}

func NewCollector(
	source SnapshotSource,
	activeWindow time.Duration,
) *Collector {
	if activeWindow <= 0 {
		activeWindow = 3 * time.Minute
	}
	return &Collector{
		source:           source,
		activeWindow:     activeWindow,
		historyWindow:    DefaultHistoryWindow,
		interfaces:       make(map[string]struct{}),
		peers:            make(map[string]*peerState),
		histories:        make(map[string]*interfaceHistory),
		trafficBaselines: make(map[string]trafficBaseline),
		subscribers:      make(map[uint64]*collectorSubscriber),
		clock:            time.Now,
	}
}

// Run is the sole periodic WireGuard sampling loop. HTTP status and SSE
// handlers only read the in-memory snapshot populated here.
func (collector *Collector) Run(ctx context.Context) {
	if collector == nil || collector.source == nil {
		return
	}
	collector.sampleWithTimeout(ctx)
	ticker := time.NewTicker(DefaultStatusInterval)
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

// InterfaceStatus only reads the latest background sample and never queries
// the kernel itself.
func (collector *Collector) InterfaceStatus(
	_ context.Context,
	config model.Interface,
) model.InterfaceRuntimeStatus {
	if collector == nil || collector.source == nil {
		return unavailableInterface(config, "运行状态采集器未启用")
	}
	return collector.interfaceStatus(config, collector.now())
}

func (collector *Collector) now() time.Time {
	return collector.clock().UTC()
}

func (collector *Collector) Sample(ctx context.Context, now time.Time) error {
	if collector == nil || collector.source == nil {
		return fmt.Errorf("wg status collector is not configured")
	}
	snapshot, err := collector.source.Snapshot(ctx)
	if err != nil {
		collector.markUnavailable(now, "无法通过内核接口读取 WireGuard 运行状态；请确认进程有权限访问网络接口")
		return err
	}
	interfaces := make(map[string]struct{}, len(snapshot.Devices))
	peers := make([]peerSample, 0)
	for _, device := range snapshot.Devices {
		interfaces[device.Name] = struct{}{}
		for _, peer := range device.Peers {
			peers = append(peers, peerSample{
				interfaceName: device.Name,
				publicKey:     peer.PublicKey,
				endpoint:      peer.Endpoint,
				lastHandshake: peer.LastHandshake,
				receivedBytes: peer.ReceivedBytes,
				sentBytes:     peer.SentBytes,
			})
		}
	}

	collector.mu.Lock()
	statusChanged := !collector.available || collector.message != "" ||
		!sameInterfaceSet(collector.interfaces, interfaces)
	collector.available = true
	collector.message = ""
	collector.sampledAt = now
	collector.interfaces = interfaces
	seen := make(map[string]struct{}, len(peers))
	for _, sample := range peers {
		key := statusKey(sample.interfaceName, sample.publicKey)
		seen[key] = struct{}{}
		if collector.ingestLocked(sample, now) {
			statusChanged = true
		}
		if _, ok := collector.trafficBaselines[key]; !ok {
			collector.trafficBaselines[key] = trafficBaseline{
				receivedBytes: sample.receivedBytes,
				sentBytes:     sample.sentBytes,
				sampledAt:     now,
			}
		}
	}
	for key := range collector.peers {
		if _, ok := seen[key]; !ok {
			delete(collector.peers, key)
			delete(collector.trafficBaselines, key)
			statusChanged = true
		}
	}
	trafficDue := collector.trafficDueLocked(now)
	if trafficDue {
		collector.recordTrafficLocked(interfaces, peers, now)
	}
	collector.pruneHistoriesLocked(now.Add(-collector.historyWindow))
	collector.mu.Unlock()
	if statusChanged {
		collector.notifyStatusSubscribers()
	}
	if trafficDue {
		collector.notifyTrafficSubscribers()
	}
	return nil
}

func (collector *Collector) markUnavailable(now time.Time, message string) {
	collector.mu.Lock()
	statusChanged := collector.available || collector.message != message ||
		len(collector.interfaces) != 0
	collector.available = false
	collector.message = message
	collector.sampledAt = now
	collector.interfaces = make(map[string]struct{})
	collector.trafficBaselines = make(map[string]trafficBaseline)
	trafficDue := collector.trafficDueLocked(now)
	collector.pruneHistoriesLocked(now.Add(-collector.historyWindow))
	collector.mu.Unlock()
	if statusChanged {
		collector.notifyStatusSubscribers()
	}
	if trafficDue {
		collector.notifyTrafficSubscribers()
	}
}

func (collector *Collector) trafficDueLocked(now time.Time) bool {
	if collector.lastTrafficAt.IsZero() {
		collector.lastTrafficAt = now
		return false
	}
	if now.Sub(collector.lastTrafficAt) < DefaultTrafficInterval {
		return false
	}
	collector.lastTrafficAt = now
	return true
}

func (collector *Collector) recordTrafficLocked(
	interfaces map[string]struct{},
	peers []peerSample,
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
		key := statusKey(sample.interfaceName, sample.publicKey)
		baseline, baselineAvailable := collector.trafficBaselines[key]
		state.receiveRate = 0
		state.sendRate = 0
		if baselineAvailable {
			elapsed := now.Sub(baseline.sampledAt).Seconds()
			if elapsed > 0 && sample.receivedBytes >= baseline.receivedBytes {
				state.receiveRate = float64(sample.receivedBytes-baseline.receivedBytes) / elapsed
			}
			if elapsed > 0 && sample.sentBytes >= baseline.sentBytes {
				state.sendRate = float64(sample.sentBytes-baseline.sentBytes) / elapsed
			}
		}
		collector.trafficBaselines[key] = trafficBaseline{
			receivedBytes: sample.receivedBytes,
			sentBytes:     sample.sentBytes,
			sampledAt:     now,
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

func (collector *Collector) Subscribe() (Subscription, func()) {
	if collector == nil {
		return Subscription{}, func() {}
	}
	collector.subscribersMu.Lock()
	collector.nextSubscriberID++
	id := collector.nextSubscriberID
	subscriber := &collectorSubscriber{
		status:  make(chan struct{}, 1),
		traffic: make(chan struct{}, 1),
	}
	collector.subscribers[id] = subscriber
	collector.subscribersMu.Unlock()
	return Subscription{
			Status:  subscriber.status,
			Traffic: subscriber.traffic,
		}, func() {
			collector.subscribersMu.Lock()
			delete(collector.subscribers, id)
			collector.subscribersMu.Unlock()
		}
}

func (collector *Collector) notifyStatusSubscribers() {
	if collector == nil {
		return
	}
	collector.subscribersMu.Lock()
	defer collector.subscribersMu.Unlock()
	for _, subscriber := range collector.subscribers {
		select {
		case subscriber.status <- struct{}{}:
		default:
		}
	}
}

func (collector *Collector) notifyTrafficSubscribers() {
	if collector == nil {
		return
	}
	collector.subscribersMu.Lock()
	defer collector.subscribersMu.Unlock()
	for _, subscriber := range collector.subscribers {
		select {
		case subscriber.traffic <- struct{}{}:
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

func (collector *Collector) ingestLocked(sample peerSample, now time.Time) bool {
	key := statusKey(sample.interfaceName, sample.publicKey)
	state := collector.peers[key]
	endpoint := sample.endpoint
	active := !sample.lastHandshake.IsZero() &&
		now.Sub(sample.lastHandshake) >= 0 &&
		now.Sub(sample.lastHandshake) <= collector.activeWindow
	changed := state == nil
	if state == nil {
		state = &peerState{
			active:     active,
			stateSince: stateStart(sample.lastHandshake, now, active, collector.activeWindow),
		}
		collector.peers[key] = state
	} else {
		changed = state.endpoint != endpoint ||
			!state.lastHandshake.Equal(sample.lastHandshake) ||
			state.active != active
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
	state.endpoint = endpoint
	state.lastHandshake = sample.lastHandshake
	state.receivedBytes = sample.receivedBytes
	state.sentBytes = sample.sentBytes
	return changed
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

func sameInterfaceSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for name := range left {
		if _, ok := right[name]; !ok {
			return false
		}
	}
	return true
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
