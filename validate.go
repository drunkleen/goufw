package goufw

import (
	"fmt"
	"net/netip"
)

// Ptr returns a pointer to v. Useful for RuleFilter optional pointer fields.
//
//	filter := RuleFilter{Protocol: Ptr(TCP)}
func Ptr[T any](v T) *T {
	return &v
}

// ValidatePort returns ErrInvalidPort if port is 0 or exceeds 65535.
func ValidatePort(port uint16) error {
	if port == 0 || port > 65535 {
		return fmt.Errorf("%w: %d", ErrInvalidPort, port)
	}
	return nil
}

// ValidateProtocol returns ErrInvalidProtocol if proto is not TCP, UDP, or Both.
func ValidateProtocol(proto Protocol) error {
	if proto != TCP && proto != UDP && proto != Both {
		return fmt.Errorf("%w: %s", ErrInvalidProtocol, string(proto))
	}
	return nil
}

// ValidateDirection returns ErrInvalidDirection if dir is not From or To.
func ValidateDirection(direction Direction) error {
	if direction != From && direction != To {
		return fmt.Errorf("%w: %s", ErrInvalidDirection, string(direction))
	}
	return nil
}

// ValidateIP returns ErrInvalidIP if ip is the zero value.
func ValidateIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return ErrInvalidIP
	}
	return nil
}

// ValidatePrefix returns ErrInvalidPrefix if prefix is the zero value.
func ValidatePrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return ErrInvalidPrefix
	}
	return nil
}

// RuleID returns a deterministic unique identifier for a rule.
// Used internally by the mock backend for deduplication.
func RuleID(kind RuleKind, action Action, proto Protocol, direction Direction, port uint16, ip netip.Addr, prefix netip.Prefix) string {
	switch kind {
	case RuleKindPort:
		return fmt.Sprintf("port:%s:%s:%d", action, proto, port)
	case RuleKindIP:
		return fmt.Sprintf("ip:%s:%s:%s", action, direction, ip.String())
	case RuleKindIPPort:
		return fmt.Sprintf("ip_port:%s:%s:%s:%d:%s", action, direction, proto, port, ip.String())
	case RuleKindIPRange:
		return fmt.Sprintf("ip_range:%s:%s:%s", action, direction, prefix.String())
	default:
		return ""
	}
}
