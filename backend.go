package goufw

import "net/netip"

type backend interface {
	AllowPort(port uint16, protocol Protocol, comment string) error
	DenyPort(port uint16, protocol Protocol, comment string) error
	DeletePort(port uint16, protocol Protocol) (bool, error)

	AllowIP(ip netip.Addr, direction Direction, comment string) error
	DenyIP(ip netip.Addr, direction Direction, comment string) error
	DeleteIP(ip netip.Addr, direction Direction) (bool, error)

	AllowIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction, comment string) error
	DenyIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction, comment string) error
	DeleteIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction) (bool, error)

	AllowIPRange(cidr netip.Prefix, direction Direction, comment string) error
	DenyIPRange(cidr netip.Prefix, direction Direction, comment string) error
	DeleteIPRange(cidr netip.Prefix, direction Direction) (bool, error)

	GetPortStatus(port uint16, protocol Protocol) (Status, error)
	GetIPStatus(ip netip.Addr, direction Direction) (Status, error)
	GetIPPortStatus(ip netip.Addr, port uint16, protocol Protocol, direction Direction) (Status, error)
	GetIPRangeStatus(cidr netip.Prefix, direction Direction) (Status, error)

	ListAllRules() ([]Rule, error)
	ListRules(filter RuleFilter) ([]Rule, error)
	ListAllowedPorts() ([]uint16, error)
	ListDeniedPorts() ([]uint16, error)
	ListAllowedIPs(direction Direction) ([]netip.Addr, error)
	ListDeniedIPs(direction Direction) ([]netip.Addr, error)
	ListAllowedIPRanges(direction Direction) ([]netip.Prefix, error)
	ListDeniedIPRanges(direction Direction) ([]netip.Prefix, error)

	Enable() error
	Disable() error
	Reload() error
	Reset() error
	Flush() error
	IsInstalled() (bool, error)
	IsEnabled() (bool, error)
	RawStatus() (string, error)
	DefaultDenyIncoming() error
	DefaultAllowOutgoing() error
}
