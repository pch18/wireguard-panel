package mtuprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

const (
	DefaultTarget      = "8.8.8.8"
	minimumIPv4PathMTU = 576
	maximumIPv4PathMTU = 1500
	wireGuardOverhead  = 80
	probeMethod        = "icmp-echo-df"
)

var (
	ErrUnavailable = errors.New("MTU 探测不可用")
	ErrNoResponse  = errors.New("MTU 探测目标无响应")
)

type Result struct {
	Target        string `json:"target"`
	Method        string `json:"method"`
	PathMTU       int    `json:"pathMTU"`
	WireGuardMTU  int    `json:"wireGuardMTU"`
	OverheadBytes int    `json:"overheadBytes"`
}

type Detector interface {
	Detect(context.Context) (Result, error)
}

type packetProbe func(context.Context, net.IP, int) (bool, error)

type detector struct {
	mu    sync.Mutex
	probe packetProbe
}

func NewDetector() Detector {
	return &detector{probe: probeIPv4Packet}
}

func (detector *detector) Detect(ctx context.Context) (Result, error) {
	detector.mu.Lock()
	defer detector.mu.Unlock()

	target := net.ParseIP(DefaultTarget).To4()
	if target == nil {
		return Result{}, fmt.Errorf("%w: 探测目标不是 IPv4 地址", ErrUnavailable)
	}
	reachable, err := detector.probe(ctx, target, minimumIPv4PathMTU)
	if err != nil {
		return Result{}, err
	}
	if !reachable {
		return Result{}, fmt.Errorf(
			"%w: %s 没有回应 %d 字节 DF ICMP 请求",
			ErrNoResponse,
			DefaultTarget,
			minimumIPv4PathMTU,
		)
	}

	low, high := minimumIPv4PathMTU, maximumIPv4PathMTU
	for low < high {
		candidate := (low + high + 1) / 2
		accepted, probeErr := detector.probe(ctx, target, candidate)
		if probeErr != nil {
			return Result{}, probeErr
		}
		if accepted {
			low = candidate
		} else {
			high = candidate - 1
		}
	}

	return Result{
		Target:        DefaultTarget,
		Method:        probeMethod,
		PathMTU:       low,
		WireGuardMTU:  low - wireGuardOverhead,
		OverheadBytes: wireGuardOverhead,
	}, nil
}
