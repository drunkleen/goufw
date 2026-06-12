package goufw

import (
	"net/netip"
)

// Firewall is the main API for managing UFW rules.
// Create one with New or NewWithConfig.
type Firewall struct {
	backend backend
}

// New creates a Firewall backed by the real UFW CLI.
// Returns ErrUFWNotFound if ufw is not installed.
//
//	fw, err := goufw.New()
func New() (*Firewall, error) {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a Firewall with the given config.
// Use Config{Backend: BackendMock} for tests without root.
//
//	fw, _ := goufw.NewWithConfig(goufw.Config{Backend: goufw.BackendMock})
func NewWithConfig(config Config) (*Firewall, error) {
	var b backend
	switch config.Backend {
	case BackendUFW:
		ub, err := newUFWBackend()
		if err != nil {
			return nil, err
		}
		b = ub
	case BackendMock:
		b = newMemBackend()
	default:
		ub, err := newUFWBackend()
		if err != nil {
			return nil, err
		}
		b = ub
	}
	return &Firewall{backend: b}, nil
}

// AllowPort adds a rule to allow traffic on port.
//
//	fw.AllowPort(22, TCP, "SSH")
func (fw *Firewall) AllowPort(port uint16, protocol Protocol, comment string) error {
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return err
	}
	return fw.backend.AllowPort(port, protocol, comment)
}

// DenyPort adds a rule to deny traffic on port.
//
//	fw.DenyPort(23, TCP, "Telnet")
func (fw *Firewall) DenyPort(port uint16, protocol Protocol, comment string) error {
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return err
	}
	return fw.backend.DenyPort(port, protocol, comment)
}

// DeletePort removes a port rule. Idempotent — returns nil if not found.
//
//	fw.DeletePort(22, TCP)
func (fw *Firewall) DeletePort(port uint16, protocol Protocol) error {
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return err
	}
	_, err := fw.backend.DeletePort(port, protocol)
	return err
}

// AllowIP adds a rule to allow traffic from/to ip.
//
//	fw.AllowIP(ip, From, "trusted source")
func (fw *Firewall) AllowIP(ip netip.Addr, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.backend.AllowIP(ip, direction, comment)
}

// DenyIP adds a rule to deny traffic from/to ip.
//
//	fw.DenyIP(ip, From, "blocked host")
func (fw *Firewall) DenyIP(ip netip.Addr, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.backend.DenyIP(ip, direction, comment)
}

// DeleteIP removes an IP rule. Idempotent — returns nil if not found.
//
//	fw.DeleteIP(ip, From)
func (fw *Firewall) DeleteIP(ip netip.Addr, direction Direction) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	_, err := fw.backend.DeleteIP(ip, direction)
	return err
}

// AllowIPPort adds a rule to allow traffic from/to ip on a specific port+protocol.
//
//	fw.AllowIPPort(ip, 22, TCP, From, "SSH from trusted")
func (fw *Firewall) AllowIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.backend.AllowIPPort(ip, port, protocol, direction, comment)
}

// DenyIPPort adds a rule to deny traffic from/to ip on a specific port+protocol.
//
//	fw.DenyIPPort(ip, 3306, TCP, From, "Block MySQL")
func (fw *Firewall) DenyIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.backend.DenyIPPort(ip, port, protocol, direction, comment)
}

// DeleteIPPort removes an IP+port rule. Idempotent — returns nil if not found.
//
//	fw.DeleteIPPort(ip, 22, TCP, From)
func (fw *Firewall) DeleteIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	_, err := fw.backend.DeleteIPPort(ip, port, protocol, direction)
	return err
}

// AllowIPRange adds a rule to allow traffic from/to a CIDR range.
//
//	fw.AllowIPRange(cidr, From, "LAN")
func (fw *Firewall) AllowIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	if err := ValidatePrefix(cidr); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.backend.AllowIPRange(cidr, direction, comment)
}

// DenyIPRange adds a rule to deny traffic from/to a CIDR range.
//
//	fw.DenyIPRange(cidr, From, "blocked subnet")
func (fw *Firewall) DenyIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	if err := ValidatePrefix(cidr); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.backend.DenyIPRange(cidr, direction, comment)
}

// BlockIPRange is an alias for DenyIPRange.
//
//	fw.BlockIPRange(cidr, To, "blocked subnet")
func (fw *Firewall) BlockIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	return fw.DenyIPRange(cidr, direction, comment)
}

// DeleteIPRange removes a CIDR range rule. Idempotent — returns nil if not found.
//
//	fw.DeleteIPRange(cidr, From)
func (fw *Firewall) DeleteIPRange(cidr netip.Prefix, direction Direction) error {
	if err := ValidatePrefix(cidr); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	_, err := fw.backend.DeleteIPRange(cidr, direction)
	return err
}

// GetPortStatus returns the status for a port+protocol combo.
//
//	status, _ := fw.GetPortStatus(22, TCP) // StatusAllowed
func (fw *Firewall) GetPortStatus(port uint16, protocol Protocol) (Status, error) {
	if err := ValidatePort(port); err != nil {
		return StatusNone, err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return StatusNone, err
	}
	return fw.backend.GetPortStatus(port, protocol)
}

// GetIPStatus returns the status for an IP + direction combo.
//
//	status, _ := fw.GetIPStatus(ip, From)
func (fw *Firewall) GetIPStatus(ip netip.Addr, direction Direction) (Status, error) {
	if err := ValidateIP(ip); err != nil {
		return StatusNone, err
	}
	if err := ValidateDirection(direction); err != nil {
		return StatusNone, err
	}
	return fw.backend.GetIPStatus(ip, direction)
}

// GetIPPortStatus returns the status for an IP+port+protocol+direction combo.
//
//	status, _ := fw.GetIPPortStatus(ip, 22, TCP, From)
func (fw *Firewall) GetIPPortStatus(ip netip.Addr, port uint16, protocol Protocol, direction Direction) (Status, error) {
	if err := ValidateIP(ip); err != nil {
		return StatusNone, err
	}
	if err := ValidatePort(port); err != nil {
		return StatusNone, err
	}
	if err := ValidateProtocol(protocol); err != nil {
		return StatusNone, err
	}
	if err := ValidateDirection(direction); err != nil {
		return StatusNone, err
	}
	return fw.backend.GetIPPortStatus(ip, port, protocol, direction)
}

// GetIPRangeStatus returns the status for a CIDR + direction combo.
//
//	status, _ := fw.GetIPRangeStatus(cidr, From)
func (fw *Firewall) GetIPRangeStatus(cidr netip.Prefix, direction Direction) (Status, error) {
	if err := ValidatePrefix(cidr); err != nil {
		return StatusNone, err
	}
	if err := ValidateDirection(direction); err != nil {
		return StatusNone, err
	}
	return fw.backend.GetIPRangeStatus(cidr, direction)
}

// ListAllRules returns all current firewall rules.
//
//	rules, _ := fw.ListAllRules()
func (fw *Firewall) ListAllRules() ([]Rule, error) {
	return fw.backend.ListAllRules()
}

// ListRules returns rules matching the given filter. Nil filter fields are ignored.
//
//	tcpRules, _ := fw.ListRules(RuleFilter{Protocol: Ptr(TCP)})
func (fw *Firewall) ListRules(filter RuleFilter) ([]Rule, error) {
	return fw.backend.ListRules(filter)
}

// ListAllowedPorts returns all ports with allow rules (deduplicated).
//
//	ports, _ := fw.ListAllowedPorts()
func (fw *Firewall) ListAllowedPorts() ([]uint16, error) {
	return fw.backend.ListAllowedPorts()
}

// ListDeniedPorts returns all ports with deny rules (deduplicated).
//
//	ports, _ := fw.ListDeniedPorts()
func (fw *Firewall) ListDeniedPorts() ([]uint16, error) {
	return fw.backend.ListDeniedPorts()
}

// ListAllowedIPs returns all allowed IPs for the given direction.
//
//	ips, _ := fw.ListAllowedIPs(From)
func (fw *Firewall) ListAllowedIPs(direction Direction) ([]netip.Addr, error) {
	return fw.backend.ListAllowedIPs(direction)
}

// ListDeniedIPs returns all denied IPs for the given direction.
//
//	ips, _ := fw.ListDeniedIPs(To)
func (fw *Firewall) ListDeniedIPs(direction Direction) ([]netip.Addr, error) {
	return fw.backend.ListDeniedIPs(direction)
}

// ListAllowedIPRanges returns all allowed CIDR ranges for the given direction.
//
//	ranges, _ := fw.ListAllowedIPRanges(From)
func (fw *Firewall) ListAllowedIPRanges(direction Direction) ([]netip.Prefix, error) {
	return fw.backend.ListAllowedIPRanges(direction)
}

// ListDeniedIPRanges returns all denied CIDR ranges for the given direction.
//
//	ranges, _ := fw.ListDeniedIPRanges(To)
func (fw *Firewall) ListDeniedIPRanges(direction Direction) ([]netip.Prefix, error) {
	return fw.backend.ListDeniedIPRanges(direction)
}

// Enable activates UFW with --force.
//
//	fw.Enable()
func (fw *Firewall) Enable() error {
	return fw.backend.Enable()
}

// Disable deactivates UFW.
//
//	fw.Disable()
func (fw *Firewall) Disable() error {
	return fw.backend.Disable()
}

// Reload reloads UFW rules.
//
//	fw.Reload()
func (fw *Firewall) Reload() error {
	return fw.backend.Reload()
}

// Reset removes all UFW rules and disables UFW. Destructive.
//
//	fw.Reset()
func (fw *Firewall) Reset() error {
	return fw.backend.Reset()
}

// Flush removes all UFW rules. Alias for Reset. Destructive.
//
//	fw.Flush()
func (fw *Firewall) Flush() error {
	return fw.backend.Flush()
}

// IsInstalled checks whether the ufw binary exists on the system.
//
//	ok, _ := fw.IsInstalled()
func (fw *Firewall) IsInstalled() (bool, error) {
	return fw.backend.IsInstalled()
}

// IsEnabled checks whether UFW is currently active.
//
//	ok, _ := fw.IsEnabled()
func (fw *Firewall) IsEnabled() (bool, error) {
	return fw.backend.IsEnabled()
}

// RawStatus returns the raw output of "ufw status".
//
//	out, _ := fw.RawStatus()
func (fw *Firewall) RawStatus() (string, error) {
	return fw.backend.RawStatus()
}

// DefaultDenyIncoming sets the default policy to deny incoming traffic.
//
//	fw.DefaultDenyIncoming()
func (fw *Firewall) DefaultDenyIncoming() error {
	return fw.backend.DefaultDenyIncoming()
}

// DefaultAllowOutgoing sets the default policy to allow outgoing traffic.
//
//	fw.DefaultAllowOutgoing()
func (fw *Firewall) DefaultAllowOutgoing() error {
	return fw.backend.DefaultAllowOutgoing()
}

// Port starts a builder chain for port rules (legacy API).
//
//	fw.Port(22).Allow().TCP().Apply()
func (fw *Firewall) Port(port uint16) *PortBuilder {
	return &PortBuilder{fw: fw, port: port}
}

// IPv4 starts a builder chain for IPv4 rules (legacy API).
//
//	b, _ := fw.IPv4("192.168.1.10")
//	b.Allow().Both().Apply()
func (fw *Firewall) IPv4(ip string) (*IPv4Builder, error) {
	parsed, err := netip.ParseAddr(ip)
	if err != nil || !parsed.Is4() {
		return nil, newInvalidIPv4(ip)
	}
	return &IPv4Builder{fw: fw, ip: parsed}, nil
}

// IPv6 starts a builder chain for IPv6 rules (legacy API).
//
//	b, _ := fw.IPv6("::1")
//	b.Allow().Both().Apply()
func (fw *Firewall) IPv6(ip string) (*IPv6Builder, error) {
	parsed, err := netip.ParseAddr(ip)
	if err != nil || parsed.Is4() {
		return nil, newInvalidIPv6(ip)
	}
	return &IPv6Builder{fw: fw, ip: parsed}, nil
}
