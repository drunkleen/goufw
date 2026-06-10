package goufw

import (
	"net"
	"testing"
)

func TestNewFirewall(t *testing.T) {
	fw := New()
	if fw == nil {
		t.Fatal("expected non-nil Firewall")
	}
}

func TestProtocolString(t *testing.T) {
	if ProtocolTCP.String() != "tcp" {
		t.Fatalf("expected tcp, got %s", ProtocolTCP.String())
	}
	if ProtocolUDP.String() != "udp" {
		t.Fatalf("expected udp, got %s", ProtocolUDP.String())
	}
	if ProtocolBoth.String() != "both" {
		t.Fatalf("expected both, got %s", ProtocolBoth.String())
	}
}

func TestProtocolIsTCP(t *testing.T) {
	if !ProtocolTCP.IsTCP() {
		t.Fatal("TCP.IsTCP() should be true")
	}
	if ProtocolUDP.IsTCP() {
		t.Fatal("UDP.IsTCP() should be false")
	}
	if ProtocolBoth.IsTCP() {
		t.Fatal("Both.IsTCP() should be false")
	}
}

func TestProtocolIsUDP(t *testing.T) {
	if !ProtocolUDP.IsUDP() {
		t.Fatal("UDP.IsUDP() should be true")
	}
	if ProtocolTCP.IsUDP() {
		t.Fatal("TCP.IsUDP() should be false")
	}
	if ProtocolBoth.IsUDP() {
		t.Fatal("Both.IsUDP() should be false")
	}
}

func TestRuleStatusString(t *testing.T) {
	if RuleStatusAllowed.String() != "Allowed" {
		t.Fatalf("expected Allowed, got %s", RuleStatusAllowed.String())
	}
	if RuleStatusDenied.String() != "Denied" {
		t.Fatalf("expected Denied, got %s", RuleStatusDenied.String())
	}
	if RuleStatusNone.String() != "None" {
		t.Fatalf("expected None, got %s", RuleStatusNone.String())
	}
}

// ---------------------------------------------------------------------------
// IPv4 validation
// ---------------------------------------------------------------------------

func TestIPv4Valid(t *testing.T) {
	fw := New()
	b, err := fw.IPv4("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestIPv4RejectsIPv6(t *testing.T) {
	fw := New()
	_, err := fw.IPv4("::1")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

func TestIPv4RejectsGarbage(t *testing.T) {
	fw := New()
	_, err := fw.IPv4("not-an-ip")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

// ---------------------------------------------------------------------------
// IPv6 validation
// ---------------------------------------------------------------------------

func TestIPv6Valid(t *testing.T) {
	fw := New()
	b, err := fw.IPv6("::1")
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestIPv6RejectsIPv4(t *testing.T) {
	fw := New()
	_, err := fw.IPv6("192.168.1.10")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

func TestIPv6RejectsGarbage(t *testing.T) {
	fw := New()
	_, err := fw.IPv6("not-an-ip")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

// ---------------------------------------------------------------------------
// PortRule / IpRule construction
// ---------------------------------------------------------------------------

func TestPortRuleConstruction(t *testing.T) {
	r := PortRule{Port: 22, Protocol: ProtocolTCP, Status: RuleStatusAllowed}
	if r.Port != 22 || r.Protocol != ProtocolTCP || r.Status != RuleStatusAllowed {
		t.Fatal("PortRule fields mismatch")
	}
}

func TestIpRuleConstruction(t *testing.T) {
	ip := net.ParseIP("192.168.1.10")
	r := IpRule{IP: ip, Protocol: ProtocolBoth, Status: RuleStatusDenied}
	if !r.IP.Equal(ip) || r.Protocol != ProtocolBoth || r.Status != RuleStatusDenied {
		t.Fatal("IpRule fields mismatch")
	}
}

// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------

func TestErrorEmptyOutput(t *testing.T) {
	if errEmptyOutput.Error() != "empty output from ufw" {
		t.Fatalf("unexpected message: %s", errEmptyOutput.Error())
	}
}

func TestErrorInvalidIPv4(t *testing.T) {
	err := newInvalidIPv4("bad")
	if err.Error() != "invalid IPv4 address: bad" {
		t.Fatalf("unexpected message: %s", err.Error())
	}
}

func TestErrorCommandFailed(t *testing.T) {
	err := newCommandFailed("test", []string{"arg1", "arg2"}, "went wrong", 1)
	msg := err.Error()
	if len(msg) == 0 {
		t.Fatal("expected non-empty error message")
	}
}
