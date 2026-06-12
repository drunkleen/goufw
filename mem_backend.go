package goufw

import (
	"net/netip"
	"sync"
)

type memBackend struct {
	mu    sync.RWMutex
	rules map[string]Rule
}

func newMemBackend() *memBackend {
	return &memBackend{
		rules: make(map[string]Rule),
	}
}

func (fw *memBackend) addRule(kind RuleKind, action Action, proto Protocol, direction Direction, port uint16, ip netip.Addr, prefix netip.Prefix, comment string) error {
	id := RuleID(kind, action, proto, direction, port, ip, prefix)
	rule := Rule{
		Kind:      kind,
		Action:    action,
		Protocol:  proto,
		Direction: direction,
		Port:      port,
		IP:        ip,
		Prefix:    prefix,
		Comment:   comment,
	}
	if action == Allow {
		rule.Status = StatusAllowed
	} else {
		rule.Status = StatusDenied
	}
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if _, exists := fw.rules[id]; exists {
		return nil
	}
	fw.rules[id] = rule
	return nil
}

func (fw *memBackend) deleteRuleByID(kind RuleKind, proto Protocol, direction Direction, port uint16, ip netip.Addr, prefix netip.Prefix) (bool, error) {
	allowID := RuleID(kind, Allow, proto, direction, port, ip, prefix)
	denyID := RuleID(kind, Deny, proto, direction, port, ip, prefix)

	fw.mu.Lock()
	defer fw.mu.Unlock()

	if _, ok := fw.rules[allowID]; ok {
		delete(fw.rules, allowID)
		return true, nil
	}
	if _, ok := fw.rules[denyID]; ok {
		delete(fw.rules, denyID)
		return true, nil
	}
	return false, nil
}

func (fw *memBackend) getStatus(kind RuleKind, proto Protocol, direction Direction, port uint16, ip netip.Addr, prefix netip.Prefix) Status {
	if proto == Both && kind == RuleKindPort {
		tcpID := RuleID(kind, Allow, TCP, direction, port, ip, prefix)
		udpID := RuleID(kind, Allow, UDP, direction, port, ip, prefix)
		tcpDenyID := RuleID(kind, Deny, TCP, direction, port, ip, prefix)
		udpDenyID := RuleID(kind, Deny, UDP, direction, port, ip, prefix)

		fw.mu.RLock()
		defer fw.mu.RUnlock()

		_, hasTCPAllow := fw.rules[tcpID]
		_, hasUDPAllow := fw.rules[udpID]
		_, hasTCPDeny := fw.rules[tcpDenyID]
		_, hasUDPDeny := fw.rules[udpDenyID]

		if hasTCPDeny || hasUDPDeny {
			return StatusDenied
		}
		if hasTCPAllow && hasUDPAllow {
			return StatusAllowed
		}
		if hasTCPAllow || hasUDPAllow {
			return StatusAllowed
		}
		return StatusNone
	}

	allowID := RuleID(kind, Allow, proto, direction, port, ip, prefix)
	denyID := RuleID(kind, Deny, proto, direction, port, ip, prefix)

	fw.mu.RLock()
	defer fw.mu.RUnlock()

	_, hasAllow := fw.rules[allowID]
	_, hasDeny := fw.rules[denyID]

	if hasAllow && !hasDeny {
		return StatusAllowed
	}
	if hasDeny {
		return StatusDenied
	}
	return StatusNone
}

// --- Port rules ---

func (fw *memBackend) AllowPort(port uint16, proto Protocol, comment string) error {
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(proto); err != nil {
		return err
	}
	if proto == Both {
		if err := fw.addRule(RuleKindPort, Allow, TCP, "", port, netip.Addr{}, netip.Prefix{}, comment); err != nil {
			return err
		}
		return fw.addRule(RuleKindPort, Allow, UDP, "", port, netip.Addr{}, netip.Prefix{}, comment)
	}
	return fw.addRule(RuleKindPort, Allow, proto, "", port, netip.Addr{}, netip.Prefix{}, comment)
}

func (fw *memBackend) DenyPort(port uint16, proto Protocol, comment string) error {
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(proto); err != nil {
		return err
	}
	if proto == Both {
		if err := fw.addRule(RuleKindPort, Deny, TCP, "", port, netip.Addr{}, netip.Prefix{}, comment); err != nil {
			return err
		}
		return fw.addRule(RuleKindPort, Deny, UDP, "", port, netip.Addr{}, netip.Prefix{}, comment)
	}
	return fw.addRule(RuleKindPort, Deny, proto, "", port, netip.Addr{}, netip.Prefix{}, comment)
}

func (fw *memBackend) DeletePort(port uint16, proto Protocol) (bool, error) {
	if err := ValidatePort(port); err != nil {
		return false, err
	}
	if err := ValidateProtocol(proto); err != nil {
		return false, err
	}
	if proto == Both {
		tcpDel, err := fw.deleteRuleByID(RuleKindPort, TCP, "", port, netip.Addr{}, netip.Prefix{})
		if err != nil {
			return tcpDel, err
		}
		udpDel, err := fw.deleteRuleByID(RuleKindPort, UDP, "", port, netip.Addr{}, netip.Prefix{})
		if err != nil {
			return udpDel, err
		}
		return tcpDel || udpDel, nil
	}
	return fw.deleteRuleByID(RuleKindPort, proto, "", port, netip.Addr{}, netip.Prefix{})
}

// --- IP rules ---

func (fw *memBackend) AllowIP(ip netip.Addr, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.addRule(RuleKindIP, Allow, "", direction, 0, ip, netip.Prefix{}, comment)
}

func (fw *memBackend) DenyIP(ip netip.Addr, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.addRule(RuleKindIP, Deny, "", direction, 0, ip, netip.Prefix{}, comment)
}

func (fw *memBackend) DeleteIP(ip netip.Addr, direction Direction) (bool, error) {
	if err := ValidateIP(ip); err != nil {
		return false, err
	}
	if err := ValidateDirection(direction); err != nil {
		return false, err
	}
	return fw.deleteRuleByID(RuleKindIP, "", direction, 0, ip, netip.Prefix{})
}

// --- IP+Port rules ---

func (fw *memBackend) AllowIPPort(ip netip.Addr, port uint16, proto Protocol, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(proto); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.addRule(RuleKindIPPort, Allow, proto, direction, port, ip, netip.Prefix{}, comment)
}

func (fw *memBackend) DenyIPPort(ip netip.Addr, port uint16, proto Protocol, direction Direction, comment string) error {
	if err := ValidateIP(ip); err != nil {
		return err
	}
	if err := ValidatePort(port); err != nil {
		return err
	}
	if err := ValidateProtocol(proto); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.addRule(RuleKindIPPort, Deny, proto, direction, port, ip, netip.Prefix{}, comment)
}

func (fw *memBackend) DeleteIPPort(ip netip.Addr, port uint16, proto Protocol, direction Direction) (bool, error) {
	if err := ValidateIP(ip); err != nil {
		return false, err
	}
	if err := ValidatePort(port); err != nil {
		return false, err
	}
	if err := ValidateProtocol(proto); err != nil {
		return false, err
	}
	if err := ValidateDirection(direction); err != nil {
		return false, err
	}
	return fw.deleteRuleByID(RuleKindIPPort, proto, direction, port, ip, netip.Prefix{})
}

// --- IP Range rules ---

func (fw *memBackend) AllowIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	if err := ValidatePrefix(cidr); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.addRule(RuleKindIPRange, Allow, "", direction, 0, netip.Addr{}, cidr, comment)
}

func (fw *memBackend) DenyIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	if err := ValidatePrefix(cidr); err != nil {
		return err
	}
	if err := ValidateDirection(direction); err != nil {
		return err
	}
	return fw.addRule(RuleKindIPRange, Deny, "", direction, 0, netip.Addr{}, cidr, comment)
}

func (fw *memBackend) DeleteIPRange(cidr netip.Prefix, direction Direction) (bool, error) {
	if err := ValidatePrefix(cidr); err != nil {
		return false, err
	}
	if err := ValidateDirection(direction); err != nil {
		return false, err
	}
	return fw.deleteRuleByID(RuleKindIPRange, "", direction, 0, netip.Addr{}, cidr)
}

// --- Status queries ---

func (fw *memBackend) GetPortStatus(port uint16, proto Protocol) (Status, error) {
	if err := ValidatePort(port); err != nil {
		return StatusNone, err
	}
	if err := ValidateProtocol(proto); err != nil {
		return StatusNone, err
	}
	return fw.getStatus(RuleKindPort, proto, "", port, netip.Addr{}, netip.Prefix{}), nil
}

func (fw *memBackend) GetIPStatus(ip netip.Addr, direction Direction) (Status, error) {
	if err := ValidateIP(ip); err != nil {
		return StatusNone, err
	}
	if err := ValidateDirection(direction); err != nil {
		return StatusNone, err
	}
	return fw.getStatus(RuleKindIP, "", direction, 0, ip, netip.Prefix{}), nil
}

func (fw *memBackend) GetIPPortStatus(ip netip.Addr, port uint16, proto Protocol, direction Direction) (Status, error) {
	if err := ValidateIP(ip); err != nil {
		return StatusNone, err
	}
	if err := ValidatePort(port); err != nil {
		return StatusNone, err
	}
	if err := ValidateProtocol(proto); err != nil {
		return StatusNone, err
	}
	if err := ValidateDirection(direction); err != nil {
		return StatusNone, err
	}
	return fw.getStatus(RuleKindIPPort, proto, direction, port, ip, netip.Prefix{}), nil
}

func (fw *memBackend) GetIPRangeStatus(cidr netip.Prefix, direction Direction) (Status, error) {
	if err := ValidatePrefix(cidr); err != nil {
		return StatusNone, err
	}
	if err := ValidateDirection(direction); err != nil {
		return StatusNone, err
	}
	return fw.getStatus(RuleKindIPRange, "", direction, 0, netip.Addr{}, cidr), nil
}

// --- Listing ---

func (fw *memBackend) ListAllRules() ([]Rule, error) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	result := make([]Rule, 0, len(fw.rules))
	for _, r := range fw.rules {
		result = append(result, r)
	}
	return result, nil
}

func (fw *memBackend) ListRules(filter RuleFilter) ([]Rule, error) {
	all, err := fw.ListAllRules()
	if err != nil {
		return nil, err
	}
	var result []Rule
	for _, r := range all {
		if matchRuleFilter(r, filter) {
			result = append(result, r)
		}
	}
	return result, nil
}

func (fw *memBackend) ListAllowedPorts() ([]uint16, error) {
	rules, err := fw.ListRules(RuleFilter{Action: Ptr(Allow), Kind: Ptr(RuleKindPort)})
	if err != nil {
		return nil, err
	}
	ports := make([]uint16, 0, len(rules))
	seen := make(map[uint16]bool)
	for _, r := range rules {
		if !seen[r.Port] {
			seen[r.Port] = true
			ports = append(ports, r.Port)
		}
	}
	return ports, nil
}

func (fw *memBackend) ListDeniedPorts() ([]uint16, error) {
	rules, err := fw.ListRules(RuleFilter{Action: Ptr(Deny), Kind: Ptr(RuleKindPort)})
	if err != nil {
		return nil, err
	}
	ports := make([]uint16, 0, len(rules))
	seen := make(map[uint16]bool)
	for _, r := range rules {
		if !seen[r.Port] {
			seen[r.Port] = true
			ports = append(ports, r.Port)
		}
	}
	return ports, nil
}

func (fw *memBackend) ListAllowedIPs(direction Direction) ([]netip.Addr, error) {
	rules, err := fw.ListRules(RuleFilter{Action: Ptr(Allow), Kind: Ptr(RuleKindIP), Direction: Ptr(direction)})
	if err != nil {
		return nil, err
	}
	ips := make([]netip.Addr, 0, len(rules))
	seen := make(map[string]bool)
	for _, r := range rules {
		key := r.IP.String()
		if !seen[key] {
			seen[key] = true
			ips = append(ips, r.IP)
		}
	}
	return ips, nil
}

func (fw *memBackend) ListDeniedIPs(direction Direction) ([]netip.Addr, error) {
	rules, err := fw.ListRules(RuleFilter{Action: Ptr(Deny), Kind: Ptr(RuleKindIP), Direction: Ptr(direction)})
	if err != nil {
		return nil, err
	}
	ips := make([]netip.Addr, 0, len(rules))
	seen := make(map[string]bool)
	for _, r := range rules {
		key := r.IP.String()
		if !seen[key] {
			seen[key] = true
			ips = append(ips, r.IP)
		}
	}
	return ips, nil
}

func (fw *memBackend) ListAllowedIPRanges(direction Direction) ([]netip.Prefix, error) {
	rules, err := fw.ListRules(RuleFilter{Action: Ptr(Allow), Kind: Ptr(RuleKindIPRange), Direction: Ptr(direction)})
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(rules))
	seen := make(map[string]bool)
	for _, r := range rules {
		key := r.Prefix.String()
		if !seen[key] {
			seen[key] = true
			prefixes = append(prefixes, r.Prefix)
		}
	}
	return prefixes, nil
}

func (fw *memBackend) ListDeniedIPRanges(direction Direction) ([]netip.Prefix, error) {
	rules, err := fw.ListRules(RuleFilter{Action: Ptr(Deny), Kind: Ptr(RuleKindIPRange), Direction: Ptr(direction)})
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(rules))
	seen := make(map[string]bool)
	for _, r := range rules {
		key := r.Prefix.String()
		if !seen[key] {
			seen[key] = true
			prefixes = append(prefixes, r.Prefix)
		}
	}
	return prefixes, nil
}

// --- Management ---

func (fw *memBackend) Enable() error {
	return nil
}

func (fw *memBackend) Disable() error {
	return nil
}

func (fw *memBackend) Reload() error {
	return nil
}

func (fw *memBackend) Reset() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.rules = make(map[string]Rule)
	return nil
}

func (fw *memBackend) Flush() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.rules = make(map[string]Rule)
	return nil
}

func (fw *memBackend) IsInstalled() (bool, error) {
	return true, nil
}

func (fw *memBackend) IsEnabled() (bool, error) {
	return true, nil
}

func (fw *memBackend) RawStatus() (string, error) {
	return "Status: active\n", nil
}

func (fw *memBackend) DefaultDenyIncoming() error {
	return nil
}

func (fw *memBackend) DefaultAllowOutgoing() error {
	return nil
}
