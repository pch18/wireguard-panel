//go:build linux || darwin || freebsd || netbsd || openbsd

package mtuprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ipv4HeaderBytes = 20
	icmpHeaderBytes = 8
	probeAttempts   = 2
	probeTimeout    = 450 * time.Millisecond
)

func probeIPv4Packet(
	ctx context.Context,
	target net.IP,
	packetSize int,
) (bool, error) {
	if packetSize < ipv4HeaderBytes+icmpHeaderBytes {
		return false, fmt.Errorf("%w: 探测包长度无效", ErrUnavailable)
	}
	connection, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, fmt.Errorf(
			"%w: 无法创建 raw ICMP socket，请确认进程拥有 root 或 raw socket 权限（Linux 可授予 CAP_NET_RAW）: %v",
			ErrUnavailable,
			err,
		)
	}
	defer connection.Close()
	ipConnection, ok := connection.(*net.IPConn)
	if !ok {
		return false, fmt.Errorf("%w: raw ICMP socket 类型无效", ErrUnavailable)
	}
	rawConnection, err := ipv4.NewRawConn(ipConnection)
	if err != nil {
		return false, fmt.Errorf("%w: 初始化 raw IPv4 socket: %v", ErrUnavailable, err)
	}

	identifier, err := randomIdentifier()
	if err != nil {
		return false, err
	}
	data := make([]byte, packetSize-ipv4HeaderBytes-icmpHeaderBytes)
	for index := range data {
		data[index] = byte(index)
	}

	for attempt := 0; attempt < probeAttempts; attempt++ {
		sequence := packetSize + attempt
		message := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: identifier, Seq: sequence, Data: data},
		}
		payload, marshalErr := message.Marshal(nil)
		if marshalErr != nil {
			return false, fmt.Errorf("%w: 生成 ICMP 探测包: %v", ErrUnavailable, marshalErr)
		}
		header := &ipv4.Header{
			Version:  ipv4.Version,
			Len:      ipv4HeaderBytes,
			TotalLen: packetSize,
			Flags:    ipv4.DontFragment,
			TTL:      64,
			Protocol: 1,
			Dst:      target,
		}
		deadline := time.Now().Add(probeTimeout)
		if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		if err := rawConnection.SetDeadline(deadline); err != nil {
			return false, fmt.Errorf("%w: 设置 ICMP 超时: %v", ErrUnavailable, err)
		}
		if err := rawConnection.WriteTo(header, payload, nil); err != nil {
			if errors.Is(err, syscall.EMSGSIZE) {
				return false, nil
			}
			return false, fmt.Errorf("%w: 发送 ICMP 探测包: %v", ErrUnavailable, err)
		}

		buffer := make([]byte, maximumIPv4PathMTU+512)
		for {
			receivedHeader, receivedPayload, _, readErr := rawConnection.ReadFrom(buffer)
			if readErr != nil {
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				if networkError, isNetworkError := readErr.(net.Error); isNetworkError && networkError.Timeout() {
					break
				}
				return false, fmt.Errorf("%w: 读取 ICMP 回应: %v", ErrUnavailable, readErr)
			}
			response, parseErr := icmp.ParseMessage(1, receivedPayload)
			if parseErr != nil {
				continue
			}
			switch response.Type {
			case ipv4.ICMPTypeEchoReply:
				echo, echoOK := response.Body.(*icmp.Echo)
				if echoOK && receivedHeader.Src.Equal(target) &&
					echo.ID == identifier && echo.Seq == sequence {
					return true, nil
				}
			case ipv4.ICMPTypeDestinationUnreachable:
				if response.Code == 4 && fragmentationMatches(
					response.Body,
					target,
					identifier,
					sequence,
				) {
					return false, nil
				}
			}
		}
	}
	return false, nil
}

func fragmentationMatches(
	body icmp.MessageBody,
	target net.IP,
	identifier int,
	sequence int,
) bool {
	unreachable, ok := body.(*icmp.DstUnreach)
	if !ok {
		return false
	}
	header, err := ipv4.ParseHeader(unreachable.Data)
	if err != nil || header.Protocol != 1 || !header.Dst.Equal(target) ||
		header.Len >= len(unreachable.Data) {
		return false
	}
	original, err := icmp.ParseMessage(1, unreachable.Data[header.Len:])
	if err != nil || original.Type != ipv4.ICMPTypeEcho {
		return false
	}
	echo, ok := original.Body.(*icmp.Echo)
	return ok && echo.ID == identifier && echo.Seq == sequence
}

func randomIdentifier() (int, error) {
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, fmt.Errorf("%w: 生成 ICMP 标识: %v", ErrUnavailable, err)
	}
	return int(binary.BigEndian.Uint16(value[:])), nil
}
