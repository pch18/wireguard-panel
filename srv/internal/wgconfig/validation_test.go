package wgconfig

import (
	"errors"
	"strings"
	"testing"

	"wireguard-panel/internal/model"
)

func TestInterfaceNameMatchesNativeFilenameConstraints(t *testing.T) {
	for _, valid := range []string{"wg0", "Tokyo-2", "office_vpn", "A12345678901234"} {
		if err := ValidateInterfaceName(valid); err != nil {
			t.Errorf("valid Interface name %q was rejected: %v", valid, err)
		}
	}
	for _, invalidName := range []string{
		"",
		" wg0 ",
		"tokyo vpn",
		"wg0.conf",
		"tokyo.jp",
		"東京",
		"A123456789012345",
	} {
		if err := ValidateInterfaceName(invalidName); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("invalid Interface name %q returned %v", invalidName, err)
		}
	}
}

func TestNormalizeInterfaceRequiresCIDRForPeerDefaultAllowedIPs(t *testing.T) {
	input := model.InterfaceInput{
		PrivateKey:       testPrivateKey(t),
		ClientAllowedIPs: []string{"10.0.0.0/8", "not-a-cidr"},
	}
	if _, err := NormalizeInterface(input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid Peer default CIDR returned %v", err)
	}
}

func TestNormalizeInterfaceAllowsNoAddress(t *testing.T) {
	normalized, err := NormalizeInterface(model.InterfaceInput{
		PrivateKey: testPrivateKey(t),
		Address:    []string{},
	})
	if err != nil {
		t.Fatalf("Interface without Address was rejected: %v", err)
	}
	if len(normalized.Address) != 0 {
		t.Fatalf("empty Interface Address changed unexpectedly: %#v", normalized.Address)
	}
}

func TestNormalizeInterfaceRequiresMaskForEveryAddress(t *testing.T) {
	_, err := NormalizeInterface(model.InterfaceInput{
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.0.0.1"},
	})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "CIDR") {
		t.Fatalf("Interface Address without mask returned %v", err)
	}
}

func TestPeerPublicKeyPathIsCanonicalURLSafeAndReversible(t *testing.T) {
	publicKey := "//////////////////////////////////////////8="
	path, err := EncodePeerPublicKeyPath(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(path, "/+=") || len(path) != 43 {
		t.Fatalf("path is not canonical Base64URL: %q", path)
	}
	decoded, err := DecodePeerPublicKeyPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != publicKey {
		t.Fatalf("decoded key %q, want %q", decoded, publicKey)
	}
	for _, invalidPath := range []string{"", publicKey, path + "=", path + "A", "not-a-key"} {
		if _, err := DecodePeerPublicKeyPath(invalidPath); err == nil {
			t.Errorf("invalid path %q was accepted", invalidPath)
		}
	}
}

func TestNormalizePeerRejectsNonCanonicalPublicKeyEncoding(t *testing.T) {
	canonical := strings.Repeat("A", 43) + "="
	nonCanonical := strings.Repeat("A", 42) + "B="
	if _, err := EncodePeerPublicKeyPath(canonical); err != nil {
		t.Fatalf("canonical key was rejected: %v", err)
	}
	if _, err := EncodePeerPublicKeyPath(nonCanonical); err == nil {
		t.Fatal("non-canonical encoding of the same key bytes was accepted")
	}
}

func TestNormalizePeerAllowsEmptyNameAndAllowedIPs(t *testing.T) {
	normalized, err := NormalizePeer(model.PeerInput{PublicKey: testPublicKey(t)})
	if err != nil {
		t.Fatalf("optional Peer fields were rejected: %v", err)
	}
	if normalized.Name != "" || len(normalized.AllowedIPs) != 0 {
		t.Fatalf("optional Peer fields were changed unexpectedly: %#v", normalized)
	}
}

func TestPeerAllowedIPsRouteRangeIsAdvisory(t *testing.T) {
	config := model.Interface{
		Address:          []string{"10.20.16.1/20", "fd20:30::1/48"},
		ClientAllowedIPs: []string{"10.20.16.0/20", "fd20:30::/48"},
		Peers: []model.Peer{{
			Name:       "inside",
			PublicKey:  "peer-a",
			AllowedIPs: []string{"10.20.31.0/24", "fd20:30:0:1::/64"},
		}},
	}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("contained IPv4/IPv6 prefixes were rejected: %v", err)
	}

	config.Peers[0].AllowedIPs = []string{"10.20.16.0/19"}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("advisory route range rejected an outside prefix: %v", err)
	}
}

func TestConfiguredPeerRangeAllowsAnUnconfiguredAddressFamily(t *testing.T) {
	config := model.Interface{
		Address:          []string{"10.0.0.1/8"},
		ClientAllowedIPs: []string{"192.0.2.0/24"},
		Peers: []model.Peer{{
			Name:       "IPv6 peer",
			PublicKey:  "peer-v6",
			AllowedIPs: []string{"fd00:1234::/64"},
		}},
	}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("advisory IPv4 range rejected IPv6: %v", err)
	}
}

func TestMissingPeerRouteRangeAllowsAnyValidIP(t *testing.T) {
	config := model.Interface{
		Address: []string{"10.0.0.1/8"},
		Peers: []model.Peer{{
			Name:       "unrestricted",
			PublicKey:  "peer-any",
			AllowedIPs: []string{"192.0.2.0/24", "fd00:1234::/64"},
		}},
	}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("missing route range should allow arbitrary valid IPs: %v", err)
	}
}

func TestExistingOutOfRangePeerHasNoConfigurationError(t *testing.T) {
	config := model.Interface{
		PrivateKey:       testPrivateKey(t),
		ClientAllowedIPs: []string{"10.0.0.0/8"},
		Peers: []model.Peer{{
			Name:       "legacy",
			PublicKey:  testPublicKey(t),
			AllowedIPs: []string{"192.0.2.7/32"},
		}},
	}
	if err := validateIPAssignmentsForRead(config); err != nil {
		t.Fatalf("existing out-of-range Peer should remain readable: %v", err)
	}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("advisory route range rejected the Peer: %v", err)
	}
	if _, err := Serialize(config); err != nil {
		t.Fatalf("panel-only route range warning blocked WireGuard serialization: %v", err)
	}
	problems := ConfigurationValidationErrors(config)
	if len(problems) != 0 {
		t.Fatalf("advisory route range produced configuration errors: %#v", problems)
	}
}

func TestConfigurationValidationIgnoresEveryOutOfRangePeer(t *testing.T) {
	config := model.Interface{
		PrivateKey:       testPrivateKey(t),
		ClientAllowedIPs: []string{"10.0.0.0/8"},
		Peers: []model.Peer{
			{Name: "first", PublicKey: testPublicKey(t), AllowedIPs: []string{"192.0.2.1/32"}},
			{Name: "second", PublicKey: testPublicKey(t), AllowedIPs: []string{"198.51.100.2/32"}},
		},
	}
	problems := ConfigurationValidationErrors(config)
	if len(problems) != 0 {
		t.Fatalf("advisory route ranges produced configuration errors: %#v", problems)
	}
}

func TestNestedPeerAllowedIPsAreAllowedButExactDuplicatesAreRejected(t *testing.T) {
	config := model.Interface{
		Peers: []model.Peer{
			{Name: "first", PublicKey: "peer-a", AllowedIPs: []string{"10.30.0.0/24"}},
			{Name: "second", PublicKey: "peer-b", AllowedIPs: []string{"10.30.0.128/25"}},
		},
	}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("nested Peer prefixes were rejected: %v", err)
	}
	config.Peers[1].AllowedIPs = []string{"10.30.0.0/24"}
	if err := validateIPAssignments(config); !errors.Is(err, ErrConflict) ||
		!strings.Contains(err.Error(), "重复") {
		t.Fatalf("duplicate Peer prefixes returned %v", err)
	}
}

func TestCanonicalDuplicateAllowedIPsWithinOnePeerAreRejected(t *testing.T) {
	config := model.Interface{Peers: []model.Peer{{
		Name:       "duplicate",
		PublicKey:  "peer-a",
		AllowedIPs: []string{"10.32.0.7/24", "10.32.0.0/24"},
	}}}
	if err := validateIPAssignments(config); !errors.Is(err, ErrConflict) ||
		!strings.Contains(err.Error(), "重复") {
		t.Fatalf("canonical duplicate in one Peer returned %v", err)
	}
}

func TestPeerPrefixMayContainInterfaceAddressUnlessItIsTheSameHost(t *testing.T) {
	config := model.Interface{
		Address: []string{"10.31.0.1/24"},
		Peers: []model.Peer{{
			Name: "router", PublicKey: "peer-a", AllowedIPs: []string{"10.31.0.0/24"},
		}},
	}
	if err := validateIPAssignments(config); err != nil {
		t.Fatalf("network containing Interface host was rejected: %v", err)
	}
	config.Peers[0].AllowedIPs = []string{"10.31.0.1/32"}
	if err := validateIPAssignments(config); !errors.Is(err, ErrConflict) ||
		!strings.Contains(err.Error(), "重复") {
		t.Fatalf("duplicate Interface host returned %v", err)
	}
}

func TestIPPlanPublishesConstraintsAndEveryPeerAssignment(t *testing.T) {
	plan := BuildIPPlan(model.Interface{
		Revision:         "revision-1",
		Address:          []string{"10.40.9.7/24", "fd40::1/64"},
		ClientAllowedIPs: []string{"10.40.0.0/16", "fd40::/48"},
		Peers: []model.Peer{{
			Name:       "router",
			PublicKey:  "peer-router",
			AllowedIPs: []string{"10.40.20.0/24", "fd40:0:0:20::/64"},
		}},
	})
	if len(plan.AllowedRanges) != 2 || plan.AllowedRanges[0] != "10.40.0.0/16" {
		t.Fatalf("unexpected allowed ranges: %#v", plan.AllowedRanges)
	}
	if plan.Revision != "revision-1" {
		t.Fatalf("unexpected IP plan revision: %q", plan.Revision)
	}
	if len(plan.Assignments) != 2 ||
		plan.Assignments[0].AllowedIP != "10.40.20.0/24" ||
		plan.Assignments[0].PeerName != "router" {
		t.Fatalf("unexpected assignments: %#v", plan.Assignments)
	}
}
