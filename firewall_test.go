package goufw

import (
	"net/netip"
	"testing"
)

func newForTest(t *testing.T) *Firewall {
	t.Helper()
	fw, err := NewWithConfig(Config{Backend: BackendMock})
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func TestNew(t *testing.T) {
	fw, err := NewWithConfig(Config{Backend: BackendMock})
	if err != nil {
		t.Fatal(err)
	}
	if fw == nil {
		t.Fatal("expected non-nil Firewall")
	}
}

func TestValidationErrors(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("192.168.1.1")

	if err := fw.AllowPort(0, TCP, ""); err == nil {
		t.Error("expected error for port 0")
	}
	if err := fw.AllowPort(22, "invalid", ""); err == nil {
		t.Error("expected error for invalid protocol")
	}
	if err := fw.AllowIP(netip.Addr{}, From, ""); err == nil {
		t.Error("expected error for zero IP")
	}
	if err := fw.AllowIP(ip, "invalid", ""); err == nil {
		t.Error("expected error for invalid direction")
	}
	cidr := netip.Prefix{}
	if err := fw.AllowIPRange(cidr, From, ""); err == nil {
		t.Error("expected error for zero prefix")
	}
	if err := fw.AllowIPPort(ip, 0, TCP, From, ""); err == nil {
		t.Error("expected error for port 0")
	}
	if err := fw.DenyIPPort(ip, 22, "bad", From, ""); err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestAllowPort(t *testing.T) {
	fw := newForTest(t)

	if err := fw.AllowPort(22, TCP, "SSH"); err != nil {
		t.Fatal(err)
	}

	status, err := fw.GetPortStatus(22, TCP)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestDenyPort(t *testing.T) {
	fw := newForTest(t)

	if err := fw.DenyPort(23, TCP, "Telnet"); err != nil {
		t.Fatal(err)
	}

	status, err := fw.GetPortStatus(23, TCP)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDeletePort(t *testing.T) {
	fw := newForTest(t)

	if err := fw.AllowPort(22, TCP, "SSH"); err != nil {
		t.Fatal(err)
	}
	if err := fw.DeletePort(22, TCP); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetPortStatus(22, TCP)
	if status != StatusNone {
		t.Errorf("expected StatusNone after delete, got %s", status)
	}
}

func TestDeletePortIdempotent(t *testing.T) {
	fw := newForTest(t)

	if err := fw.DeletePort(999, TCP); err != nil {
		t.Errorf("expected nil for deleting non-existent rule, got %v", err)
	}
}

func TestAllowUDPPort(t *testing.T) {
	fw := newForTest(t)

	if err := fw.AllowPort(53, UDP, "DNS"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetPortStatus(53, UDP)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed for UDP, got %s", status)
	}

	tcpStatus, _ := fw.GetPortStatus(53, TCP)
	if tcpStatus != StatusNone {
		t.Errorf("expected StatusNone for TCP 53, got %s", tcpStatus)
	}
}

func TestAllowPortBoth(t *testing.T) {
	fw := newForTest(t)

	if err := fw.AllowPort(53, Both, "DNS"); err != nil {
		t.Fatal(err)
	}

	tcpStatus, _ := fw.GetPortStatus(53, TCP)
	udpStatus, _ := fw.GetPortStatus(53, UDP)

	if tcpStatus != StatusAllowed {
		t.Errorf("expected StatusAllowed for TCP, got %s", tcpStatus)
	}
	if udpStatus != StatusAllowed {
		t.Errorf("expected StatusAllowed for UDP, got %s", udpStatus)
	}
}

func TestAllowIPFrom(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("192.168.1.10")

	if err := fw.AllowIP(ip, From, "Trusted"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPStatus(ip, From)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestDenyIPTo(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.DenyIP(ip, To, "Blocked"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPStatus(ip, To)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDeleteIP(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("192.168.1.10")

	if err := fw.AllowIP(ip, From, "Trusted"); err != nil {
		t.Fatal(err)
	}
	if err := fw.DeleteIP(ip, From); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPStatus(ip, From)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestDeleteIPIdempotent(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("192.168.1.99")

	if err := fw.DeleteIP(ip, From); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAllowIPPort(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.AllowIPPort(ip, 22, TCP, From, "SSH from trusted"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPPortStatus(ip, 22, TCP, From)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestDenyIPPort(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.DenyIPPort(ip, 3306, TCP, From, "Block MySQL"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPPortStatus(ip, 3306, TCP, From)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDeleteIPPort(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.AllowIPPort(ip, 22, TCP, From, "SSH"); err != nil {
		t.Fatal(err)
	}
	if err := fw.DeleteIPPort(ip, 22, TCP, From); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPPortStatus(ip, 22, TCP, From)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestDeleteIPPortIdempotent(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.DeleteIPPort(ip, 22, TCP, From); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAllowIPPortToDirection(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.AllowIPPort(ip, 443, TCP, To, "HTTPS to host"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPPortStatus(ip, 443, TCP, To)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestDenyIPPortToDirection(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.DenyIPPort(ip, 3306, TCP, To, "Block MySQL to host"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPPortStatus(ip, 3306, TCP, To)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDeleteIPPortToDirection(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.AllowIPPort(ip, 443, TCP, To, "HTTPS"); err != nil {
		t.Fatal(err)
	}
	if err := fw.DeleteIPPort(ip, 443, TCP, To); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPPortStatus(ip, 443, TCP, To)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestAllowIPPortFromAndToSeparate(t *testing.T) {
	fw := newForTest(t)
	ip := netip.MustParseAddr("10.0.0.1")

	if err := fw.AllowIPPort(ip, 80, TCP, From, "incoming"); err != nil {
		t.Fatal(err)
	}
	if err := fw.AllowIPPort(ip, 80, TCP, To, "outgoing"); err != nil {
		t.Fatal(err)
	}

	fromStatus, _ := fw.GetIPPortStatus(ip, 80, TCP, From)
	toStatus, _ := fw.GetIPPortStatus(ip, 80, TCP, To)

	if fromStatus != StatusAllowed {
		t.Errorf("expected StatusAllowed for From, got %s", fromStatus)
	}
	if toStatus != StatusAllowed {
		t.Errorf("expected StatusAllowed for To, got %s", toStatus)
	}
}

func TestAllowIPRange(t *testing.T) {
	fw := newForTest(t)
	cidr := netip.MustParsePrefix("192.168.1.0/24")

	if err := fw.AllowIPRange(cidr, From, "LAN"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPRangeStatus(cidr, From)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestBlockIPRange(t *testing.T) {
	fw := newForTest(t)
	cidr := netip.MustParsePrefix("10.0.0.0/8")

	if err := fw.BlockIPRange(cidr, To, "Blocked subnet"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPRangeStatus(cidr, To)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDenyIPRange(t *testing.T) {
	fw := newForTest(t)
	cidr := netip.MustParsePrefix("172.16.0.0/12")

	if err := fw.DenyIPRange(cidr, From, "blocked"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPRangeStatus(cidr, From)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDeleteIPRange(t *testing.T) {
	fw := newForTest(t)
	cidr := netip.MustParsePrefix("192.168.1.0/24")

	if err := fw.AllowIPRange(cidr, From, "LAN"); err != nil {
		t.Fatal(err)
	}
	if err := fw.DeleteIPRange(cidr, From); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPRangeStatus(cidr, From)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestDeleteIPRangeIdempotent(t *testing.T) {
	fw := newForTest(t)
	cidr := netip.MustParsePrefix("10.0.0.0/8")

	if err := fw.DeleteIPRange(cidr, From); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestListAllRules(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	fw.AllowPort(80, TCP, "HTTP")
	fw.DenyPort(23, TCP, "Telnet")

	rules, err := fw.ListAllRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}
}

func TestListRulesFiltered(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	fw.AllowPort(80, TCP, "HTTP")
	fw.DenyPort(23, TCP, "Telnet")
	ip := netip.MustParseAddr("192.168.1.1")
	fw.AllowIP(ip, From, "Trusted")

	tcpProto := TCP
	rules, err := fw.ListRules(RuleFilter{Protocol: &tcpProto})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Errorf("expected 3 TCP rules, got %d", len(rules))
	}

	allow := Allow
	rules, err = fw.ListRules(RuleFilter{Action: &allow})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Errorf("expected 3 allow rules, got %d", len(rules))
	}
}

func TestListAllowedPorts(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	fw.AllowPort(80, TCP, "HTTP")
	fw.DenyPort(23, TCP, "Telnet")

	ports, err := fw.ListAllowedPorts()
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 allowed ports, got %d", len(ports))
	}
}

func TestListDeniedPorts(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	fw.DenyPort(23, TCP, "Telnet")
	fw.DenyPort(135, TCP, "RPC")

	ports, err := fw.ListDeniedPorts()
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 denied ports, got %d", len(ports))
	}
}

func TestListAllowedIPs(t *testing.T) {
	fw := newForTest(t)

	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("10.0.0.1")
	fw.AllowIP(ip1, From, "Trusted A")
	fw.AllowIP(ip2, From, "Trusted B")

	ips, err := fw.ListAllowedIPs(From)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Errorf("expected 2 allowed IPs, got %d", len(ips))
	}
}

func TestListDeniedIPs(t *testing.T) {
	fw := newForTest(t)

	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")
	fw.DenyIP(ip1, To, "Bad A")
	fw.DenyIP(ip2, To, "Bad B")

	ips, err := fw.ListDeniedIPs(To)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Errorf("expected 2 denied IPs, got %d", len(ips))
	}
}

func TestListAllowedIPRanges(t *testing.T) {
	fw := newForTest(t)

	cidr1 := netip.MustParsePrefix("192.168.1.0/24")
	cidr2 := netip.MustParsePrefix("10.0.0.0/8")
	fw.AllowIPRange(cidr1, From, "LAN")
	fw.AllowIPRange(cidr2, From, "Corp")

	ranges, err := fw.ListAllowedIPRanges(From)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 {
		t.Errorf("expected 2 allowed ranges, got %d", len(ranges))
	}
}

func TestListDeniedIPRanges(t *testing.T) {
	fw := newForTest(t)

	cidr := netip.MustParsePrefix("10.0.0.0/8")
	fw.BlockIPRange(cidr, To, "Blocked")

	ranges, err := fw.ListDeniedIPRanges(To)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 {
		t.Errorf("expected 1 denied range, got %d", len(ranges))
	}
}

func TestStatusAllowed(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	status, _ := fw.GetPortStatus(22, TCP)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestStatusDenied(t *testing.T) {
	fw := newForTest(t)

	fw.DenyPort(23, TCP, "Telnet")
	status, _ := fw.GetPortStatus(23, TCP)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestStatusNone(t *testing.T) {
	fw := newForTest(t)

	status, _ := fw.GetPortStatus(99, TCP)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestFlush(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	fw.AllowPort(80, TCP, "HTTP")
	fw.DenyPort(23, TCP, "Telnet")

	if err := fw.Flush(); err != nil {
		t.Fatal(err)
	}

	rules, _ := fw.ListAllRules()
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after flush, got %d", len(rules))
	}
}

func TestIPv6(t *testing.T) {
	fw := newForTest(t)

	ip := netip.MustParseAddr("2001:db8::1")
	if err := fw.AllowIP(ip, From, "IPv6 source"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPStatus(ip, From)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed for IPv6, got %s", status)
	}
}

func TestIPv6CIDR(t *testing.T) {
	fw := newForTest(t)

	cidr := netip.MustParsePrefix("2001:db8::/32")
	if err := fw.AllowIPRange(cidr, From, "IPv6 range"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPRangeStatus(cidr, From)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed for IPv6 CIDR, got %s", status)
	}
}

func TestDuplicatePortIdempotency(t *testing.T) {
	fw := newForTest(t)

	if err := fw.AllowPort(22, TCP, "SSH"); err != nil {
		t.Fatal(err)
	}
	if err := fw.AllowPort(22, TCP, "SSH again"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetPortStatus(22, TCP)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}

	rules, _ := fw.ListAllRules()
	count := 0
	for _, r := range rules {
		if r.Kind == RuleKindPort && r.Port == 22 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 rule for port 22, got %d", count)
	}
}

func TestBuilderAllowChain(t *testing.T) {
	fw := newForTest(t)

	if err := fw.Port(22).Allow().TCP().Apply(); err != nil {
		t.Fatal(err)
	}
	status, _ := fw.Port(22).Status().TCP()
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestBuilderDenyChain(t *testing.T) {
	fw := newForTest(t)

	if err := fw.Port(23).Deny().TCP().Apply(); err != nil {
		t.Fatal(err)
	}
	status, _ := fw.Port(23).Status().TCP()
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestBuilderDeleteChain(t *testing.T) {
	fw := newForTest(t)

	fw.AllowPort(22, TCP, "SSH")
	deleted, err := fw.Port(22).Delete().TCP().Apply()
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}

	status, _ := fw.GetPortStatus(22, TCP)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestBuilderDeleteMissing(t *testing.T) {
	fw := newForTest(t)

	deleted, err := fw.Port(999).Delete().TCP().Apply()
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Error("expected deleted=false for missing rule")
	}
}

func TestIPv4Builder(t *testing.T) {
	fw := newForTest(t)

	b, err := fw.IPv4("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestIPv4RejectsIPv6(t *testing.T) {
	fw := newForTest(t)

	_, err := fw.IPv4("::1")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

func TestIPv4RejectsGarbage(t *testing.T) {
	fw := newForTest(t)

	_, err := fw.IPv4("not-an-ip")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

func TestIPv6Builder(t *testing.T) {
	fw := newForTest(t)

	b, err := fw.IPv6("::1")
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		t.Fatal("expected non-nil builder")
	}
}

func TestIPv6RejectsIPv4(t *testing.T) {
	fw := newForTest(t)

	_, err := fw.IPv6("192.168.1.10")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

func TestIPv6RejectsGarbage(t *testing.T) {
	fw := newForTest(t)

	_, err := fw.IPv6("not-an-ip")
	if _, ok := err.(*UfwError); !ok {
		t.Fatal("expected UfwError")
	}
}

func TestMockBackendDefaultMethods(t *testing.T) {
	fw := newForTest(t)

	if err := fw.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := fw.Disable(); err != nil {
		t.Fatal(err)
	}
	if err := fw.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := fw.Reset(); err != nil {
		t.Fatal(err)
	}
	if err := fw.DefaultDenyIncoming(); err != nil {
		t.Fatal(err)
	}
	if err := fw.DefaultAllowOutgoing(); err != nil {
		t.Fatal(err)
	}

	installed, err := fw.IsInstalled()
	if err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Error("expected IsInstalled=true for mock backend")
	}

	enabled, err := fw.IsEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Error("expected IsEnabled=true for mock backend")
	}

	status, err := fw.RawStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status != "Status: active\n" {
		t.Errorf("unexpected RawStatus: %q", status)
	}
}

func TestMockBackend(t *testing.T) {
	b := newMemBackend()

	if err := b.AllowPort(22, TCP, "SSH"); err != nil {
		t.Fatal(err)
	}
	status, err := b.GetPortStatus(22, TCP)
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}

	if _, err := b.DeletePort(22, TCP); err != nil {
		t.Fatal(err)
	}

	status, _ = b.GetPortStatus(22, TCP)
	if status != StatusNone {
		t.Errorf("expected StatusNone, got %s", status)
	}
}

func TestPort65535(t *testing.T) {
	fw := newForTest(t)

	if err := fw.AllowPort(65535, TCP, "max port"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetPortStatus(65535, TCP)
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestValidatePortZero(t *testing.T) {
	if err := ValidatePort(0); err == nil {
		t.Error("expected error for port 0")
	}
}

func TestValidatePortValid(t *testing.T) {
	if err := ValidatePort(1); err != nil {
		t.Errorf("expected nil for port 1, got %v", err)
	}
	if err := ValidatePort(65535); err != nil {
		t.Errorf("expected nil for port 65535, got %v", err)
	}
	if err := ValidatePort(8080); err != nil {
		t.Errorf("expected nil for port 8080, got %v", err)
	}
}

func TestValidateProtocolInvalid(t *testing.T) {
	if err := ValidateProtocol("invalid"); err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestValidateProtocolValid(t *testing.T) {
	if err := ValidateProtocol(TCP); err != nil {
		t.Errorf("expected nil for TCP, got %v", err)
	}
	if err := ValidateProtocol(UDP); err != nil {
		t.Errorf("expected nil for UDP, got %v", err)
	}
	if err := ValidateProtocol(Both); err != nil {
		t.Errorf("expected nil for Both, got %v", err)
	}
}

func TestValidateDirectionInvalid(t *testing.T) {
	if err := ValidateDirection("invalid"); err == nil {
		t.Error("expected error for invalid direction")
	}
}

func TestValidateDirectionValid(t *testing.T) {
	if err := ValidateDirection(From); err != nil {
		t.Errorf("expected nil for From, got %v", err)
	}
	if err := ValidateDirection(To); err != nil {
		t.Errorf("expected nil for To, got %v", err)
	}
}

func TestValidateIPInvalid(t *testing.T) {
	if err := ValidateIP(netip.Addr{}); err == nil {
		t.Error("expected error for zero IP")
	}
}

func TestValidateIPValid(t *testing.T) {
	if err := ValidateIP(netip.MustParseAddr("192.168.1.1")); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
	if err := ValidateIP(netip.MustParseAddr("::1")); err != nil {
		t.Errorf("expected nil for IPv6, got %v", err)
	}
}

func TestValidatePrefixInvalid(t *testing.T) {
	if err := ValidatePrefix(netip.Prefix{}); err == nil {
		t.Error("expected error for zero prefix")
	}
}

func TestValidatePrefixValid(t *testing.T) {
	if err := ValidatePrefix(netip.MustParsePrefix("10.0.0.0/8")); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestBuilderIPFinalizerWithProtocol(t *testing.T) {
	fw := newForTest(t)

	b, err := fw.IPv4("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Allow().TCP().Apply(); err != nil {
		t.Fatal(err)
	}
	status, _ := b.Status().TCP()
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestBuilderIPFinalizerUDP(t *testing.T) {
	fw := newForTest(t)

	b, err := fw.IPv4("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}

	if err := b.Allow().UDP().Apply(); err != nil {
		t.Fatal(err)
	}
	status, _ := b.Status().UDP()
	if status != StatusAllowed {
		t.Errorf("expected StatusAllowed, got %s", status)
	}
}

func TestBlockIPRangeDelegates(t *testing.T) {
	fw := newForTest(t)
	cidr := netip.MustParsePrefix("10.0.0.0/8")

	if err := fw.BlockIPRange(cidr, From, "blocked"); err != nil {
		t.Fatal(err)
	}

	status, _ := fw.GetIPRangeStatus(cidr, From)
	if status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", status)
	}
}

func TestDirectionFrom(t *testing.T) {
	if string(From) != "from" {
		t.Errorf("expected 'from', got %q", string(From))
	}
}

func TestDirectionTo(t *testing.T) {
	if string(To) != "to" {
		t.Errorf("expected 'to', got %q", string(To))
	}
}

func TestActionValues(t *testing.T) {
	if string(Allow) != "allow" {
		t.Errorf("expected 'allow', got %q", string(Allow))
	}
	if string(Deny) != "deny" {
		t.Errorf("expected 'deny', got %q", string(Deny))
	}
}

func TestProtocolValues(t *testing.T) {
	if string(TCP) != "tcp" {
		t.Errorf("expected 'tcp', got %q", string(TCP))
	}
	if string(UDP) != "udp" {
		t.Errorf("expected 'udp', got %q", string(UDP))
	}
	if string(Both) != "both" {
		t.Errorf("expected 'both', got %q", string(Both))
	}
}

func TestStatusValues(t *testing.T) {
	if string(StatusAllowed) != "allowed" {
		t.Errorf("expected 'allowed', got %q", string(StatusAllowed))
	}
	if string(StatusDenied) != "denied" {
		t.Errorf("expected 'denied', got %q", string(StatusDenied))
	}
	if string(StatusNone) != "none" {
		t.Errorf("expected 'none', got %q", string(StatusNone))
	}
}
