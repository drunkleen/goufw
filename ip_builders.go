package goufw

import "net/netip"

// IPv4Builder starts a builder chain for IPv4 rules (legacy API).
//
//	b, _ := fw.IPv4("192.168.1.10")
//	b.Allow().TCP().Apply()
type IPv4Builder struct {
	fw *Firewall
	ip netip.Addr
}

// Allow starts an allow chain for this IPv4 address.
func (b *IPv4Builder) Allow() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: Allow}
}

// Deny starts a deny chain for this IPv4 address.
func (b *IPv4Builder) Deny() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: Deny}
}

// Delete starts a delete chain for this IPv4 address.
func (b *IPv4Builder) Delete() *IPDeleteBuilder {
	return &IPDeleteBuilder{fw: b.fw, ip: b.ip}
}

// Status starts a status query chain for this IPv4 address.
func (b *IPv4Builder) Status() *IPStatus {
	return &IPStatus{fw: b.fw, ip: b.ip}
}

// IPv6Builder starts a builder chain for IPv6 rules (legacy API).
//
//	b, _ := fw.IPv6("::1")
//	b.Allow().Both().Apply()
type IPv6Builder struct {
	fw *Firewall
	ip netip.Addr
}

// Allow starts an allow chain for this IPv6 address.
func (b *IPv6Builder) Allow() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: Allow}
}

// Deny starts a deny chain for this IPv6 address.
func (b *IPv6Builder) Deny() *IPActionBuilder {
	return &IPActionBuilder{fw: b.fw, ip: b.ip, action: Deny}
}

// Delete starts a delete chain for this IPv6 address.
func (b *IPv6Builder) Delete() *IPDeleteBuilder {
	return &IPDeleteBuilder{fw: b.fw, ip: b.ip}
}

// Status starts a status query chain for this IPv6 address.
func (b *IPv6Builder) Status() *IPStatus {
	return &IPStatus{fw: b.fw, ip: b.ip}
}

// IPActionBuilder selects the protocol for an IP allow/deny rule.
type IPActionBuilder struct {
	fw     *Firewall
	ip     netip.Addr
	action Action
}

// TCP restricts the rule to TCP traffic.
func (b *IPActionBuilder) TCP() *IPFinalizer {
	return &IPFinalizer{fw: b.fw, ip: b.ip, action: b.action, protocol: TCP}
}

// UDP restricts the rule to UDP traffic.
func (b *IPActionBuilder) UDP() *IPFinalizer {
	return &IPFinalizer{fw: b.fw, ip: b.ip, action: b.action, protocol: UDP}
}

// Both applies the rule to both TCP and UDP traffic.
func (b *IPActionBuilder) Both() *IPFinalizer {
	return &IPFinalizer{fw: b.fw, ip: b.ip, action: b.action, protocol: Both}
}

// IPFinalizer applies an IP allow/deny rule.
type IPFinalizer struct {
	fw       *Firewall
	ip       netip.Addr
	action   Action
	protocol Protocol
}

// Apply executes the IP rule with the selected protocol.
func (f *IPFinalizer) Apply() error {
	ipStr := f.ip.String()
	actionStr := string(f.action)
	if f.protocol == Both {
		switch f.action {
		case Allow:
			return f.fw.AllowIP(f.ip, From, "")
		case Deny:
			return f.fw.DenyIP(f.ip, From, "")
		}
		return nil
	}

	if ufb, ok := f.fw.backend.(*ufwBackend); ok {
		return ufb.run(actionStr, "from", ipStr, "proto", string(f.protocol))
	}

	switch f.action {
	case Allow:
		return f.fw.AllowIP(f.ip, From, "")
	case Deny:
		return f.fw.DenyIP(f.ip, From, "")
	}
	return nil
}

// IPDeleteBuilder selects the protocol for an IP delete operation.
type IPDeleteBuilder struct {
	fw *Firewall
	ip netip.Addr
}

// TCP selects TCP protocol for delete.
func (b *IPDeleteBuilder) TCP() *IPDeleteFinalizer {
	return &IPDeleteFinalizer{fw: b.fw, ip: b.ip, protocol: TCP}
}

// UDP selects UDP protocol for delete.
func (b *IPDeleteBuilder) UDP() *IPDeleteFinalizer {
	return &IPDeleteFinalizer{fw: b.fw, ip: b.ip, protocol: UDP}
}

// Both selects both TCP and UDP for delete.
func (b *IPDeleteBuilder) Both() *IPDeleteFinalizer {
	return &IPDeleteFinalizer{fw: b.fw, ip: b.ip, protocol: Both}
}

// IPDeleteFinalizer runs an IP delete.
type IPDeleteFinalizer struct {
	fw       *Firewall
	ip       netip.Addr
	protocol Protocol
}

// Apply executes the delete. Returns true if a rule was actually removed.
func (f *IPDeleteFinalizer) Apply() (bool, error) {
	return f.fw.backend.DeleteIP(f.ip, From)
}

// IPStatus queries the status of an IP address.
type IPStatus struct {
	fw *Firewall
	ip netip.Addr
}

// TCP returns the status for TCP traffic to/from this IP.
func (s *IPStatus) TCP() (Status, error) {
	return s.fw.GetIPStatus(s.ip, From)
}

// UDP returns the status for UDP traffic to/from this IP.
func (s *IPStatus) UDP() (Status, error) {
	return s.fw.GetIPStatus(s.ip, From)
}

// Both returns the status for both TCP and UDP to/from this IP.
func (s *IPStatus) Both() (Status, error) {
	return s.fw.GetIPStatus(s.ip, From)
}
