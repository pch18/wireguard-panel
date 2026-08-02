//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package mtuprobe

import (
	"context"
	"fmt"
	"net"
)

func probeIPv4Packet(context.Context, net.IP, int) (bool, error) {
	return false, fmt.Errorf("%w: 当前系统不支持 raw IPv4 DF 探测", ErrUnavailable)
}
