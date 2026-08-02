package mtuprobe

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDetectorFindsLargestPathMTUAndSubtractsWireGuardOverhead(t *testing.T) {
	detector := &detector{probe: func(_ context.Context, target net.IP, size int) (bool, error) {
		if !target.Equal(net.ParseIP(DefaultTarget)) {
			t.Fatalf("unexpected target %s", target)
		}
		return size <= 1492, nil
	}}
	result, err := detector.Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PathMTU != 1492 || result.WireGuardMTU != 1412 ||
		result.OverheadBytes != 80 || result.Target != DefaultTarget {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDetectorRejectsSilentTargetInsteadOfGuessing(t *testing.T) {
	detector := &detector{probe: func(context.Context, net.IP, int) (bool, error) {
		return false, nil
	}}
	if _, err := detector.Detect(context.Background()); !errors.Is(err, ErrNoResponse) {
		t.Fatalf("silent target returned %v", err)
	}
}

func TestDetectorPropagatesProbeFailure(t *testing.T) {
	expected := errors.New("socket failed")
	detector := &detector{probe: func(context.Context, net.IP, int) (bool, error) {
		return false, expected
	}}
	if _, err := detector.Detect(context.Background()); !errors.Is(err, expected) {
		t.Fatalf("probe failure returned %v", err)
	}
}
