package wgconfig

import "testing"

func testKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, publicKey
}

func testPrivateKey(t *testing.T) string {
	t.Helper()
	privateKey, _ := testKeyPair(t)
	return privateKey
}

func testPublicKey(t *testing.T) string {
	t.Helper()
	_, publicKey := testKeyPair(t)
	return publicKey
}
