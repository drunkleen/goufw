package goufw

import (
	"net"
)

// ---------------------------------------------------------------------------
// IPv4Builder
// ---------------------------------------------------------------------------

type IPv4Builder struct {
	fw *Firewall
	ip net.IP
}

func (b *IPv4Builder) Allow() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: actionAllow}
}

func (b *IPv4Builder) Deny() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: actionDeny}
}

func (b *IPv4Builder) Delete() *IPDeleteBuilder {
	return &IPDeleteBuilder{ip: b.ip}
}

func (b *IPv4Builder) Status() *IPStatus {
	return &IPStatus{fw: b.fw, ip: b.ip}
}

// ---------------------------------------------------------------------------
// IPv6Builder
// ---------------------------------------------------------------------------

type IPv6Builder struct {
	fw *Firewall
	ip net.IP
}

func (b *IPv6Builder) Allow() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: actionAllow}
}

func (b *IPv6Builder) Deny() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: actionDeny}
}

func (b *IPv6Builder) Delete() *IPDeleteBuilder {
	return &IPDeleteBuilder{ip: b.ip}
}

func (b *IPv6Builder) Status() *IPStatus {
	return &IPStatus{fw: b.fw, ip: b.ip}
}

// ---------------------------------------------------------------------------
// IPActionBuilder — allow / deny
// ---------------------------------------------------------------------------

type IPActionBuilder struct {
	fw     *Firewall
	ip     net.IP
	action action
}

func (b *IPActionBuilder) TCP() *IPFinalizer {
	return &IPFinalizer{fw: b.fw, ip: b.ip, action: b.action, protocol: ProtocolTCP}
}

func (b *IPActionBuilder) UDP() *IPFinalizer {
	return &IPFinalizer{fw: b.fw, ip: b.ip, action: b.action, protocol: ProtocolUDP}
}

func (b *IPActionBuilder) Both() *IPFinalizer {
	return &IPFinalizer{fw: b.fw, ip: b.ip, action: b.action, protocol: ProtocolBoth}
}

type IPFinalizer struct {
	fw       *Firewall
	ip       net.IP
	action   action
	protocol Protocol
}

func (f *IPFinalizer) Apply() error {
	ipStr := f.ip.String()
	actionStr := actionString(f.action)
	if f.protocol == ProtocolBoth {
		return runner.run("sudo", "ufw", actionStr, "from", ipStr)
	}
	protoStr := protoString(f.protocol)
	return runner.run("sudo", "ufw", actionStr, "from", ipStr, "proto", protoStr)
}

// ---------------------------------------------------------------------------
// IPDeleteBuilder
// ---------------------------------------------------------------------------

type IPDeleteBuilder struct {
	ip net.IP
}

func (b *IPDeleteBuilder) TCP() *IPDeleteFinalizer {
	return &IPDeleteFinalizer{ip: b.ip, protocol: ProtocolTCP}
}

func (b *IPDeleteBuilder) UDP() *IPDeleteFinalizer {
	return &IPDeleteFinalizer{ip: b.ip, protocol: ProtocolUDP}
}

func (b *IPDeleteBuilder) Both() *IPDeleteFinalizer {
	return &IPDeleteFinalizer{ip: b.ip, protocol: ProtocolBoth}
}

type IPDeleteFinalizer struct {
	ip       net.IP
	protocol Protocol
}

func (f *IPDeleteFinalizer) Apply() (bool, error) {
	ipStr := f.ip.String()
	var results []deleteResult

	switch f.protocol {
	case ProtocolBoth:
		results = append(results,
			deleteResultOf("sudo", "ufw", "delete", "allow", "from", ipStr),
			deleteResultOf("sudo", "ufw", "delete", "deny", "from", ipStr),
			deleteResultOf("sudo", "ufw", "delete", "allow", "from", ipStr, "proto", "tcp"),
			deleteResultOf("sudo", "ufw", "delete", "deny", "from", ipStr, "proto", "tcp"),
			deleteResultOf("sudo", "ufw", "delete", "allow", "from", ipStr, "proto", "udp"),
			deleteResultOf("sudo", "ufw", "delete", "deny", "from", ipStr, "proto", "udp"),
		)
	case ProtocolTCP:
		results = append(results,
			deleteResultOf("sudo", "ufw", "delete", "allow", "from", ipStr, "proto", "tcp"),
			deleteResultOf("sudo", "ufw", "delete", "deny", "from", ipStr, "proto", "tcp"),
		)
	case ProtocolUDP:
		results = append(results,
			deleteResultOf("sudo", "ufw", "delete", "allow", "from", ipStr, "proto", "udp"),
			deleteResultOf("sudo", "ufw", "delete", "deny", "from", ipStr, "proto", "udp"),
		)
	}
	return combineDeleteOutcomes(results)
}

// ---------------------------------------------------------------------------
// IPStatus
// ---------------------------------------------------------------------------

type IPStatus struct {
	fw *Firewall
	ip net.IP
}

func (s *IPStatus) TCP() (RuleStatus, error) {
	rules, err := s.fw.IPs()
	if err != nil {
		return RuleStatusNone, err
	}
	return findIPStatus(rules, s.ip, ProtocolTCP), nil
}

func (s *IPStatus) UDP() (RuleStatus, error) {
	rules, err := s.fw.IPs()
	if err != nil {
		return RuleStatusNone, err
	}
	return findIPStatus(rules, s.ip, ProtocolUDP), nil
}

func (s *IPStatus) Both() (RuleStatus, error) {
	rules, err := s.fw.IPs()
	if err != nil {
		return RuleStatusNone, err
	}
	return findIPStatus(rules, s.ip, ProtocolBoth), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func protoString(p Protocol) string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	}
	return ""
}
