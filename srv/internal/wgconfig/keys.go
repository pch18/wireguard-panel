package wgconfig

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateKeyPair() (privateKey string, publicKey string, err error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return "", "", fmt.Errorf("generate WireGuard private key: %w", err)
	}
	// WireGuard/X25519 private scalars use the standard clamping operation.
	privateBytes[0] &= 248
	privateBytes[31] &= 127
	privateBytes[31] |= 64
	privateKey = base64.StdEncoding.EncodeToString(privateBytes)
	publicKey, err = PublicKeyFromPrivate(privateKey)
	if err != nil {
		return "", "", err
	}
	return privateKey, publicKey, nil
}

func GeneratePresharedKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate WireGuard preshared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func PublicKeyFromPrivate(privateKey string) (string, error) {
	privateBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(privateBytes) != 32 {
		return "", invalid("PrivateKey 必须是 WireGuard 使用的 32 字节 Base64 密钥")
	}
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", invalid("PrivateKey 无法生成 WireGuard PublicKey")
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func newPeerID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate Peer ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}
