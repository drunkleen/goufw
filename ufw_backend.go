package goufw

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

type ufwBackend struct {
	sudo    bool
	ufwPath string
}

func newUFWBackend() (*ufwBackend, error) {
	path, err := exec.LookPath("ufw")
	if err != nil {
		return nil, ErrUFWNotFound
	}
	return &ufwBackend{ufwPath: path, sudo: true}, nil
}

func (b *ufwBackend) command(args ...string) *exec.Cmd {
	var cmdArgs []string
	if b.sudo {
		cmdArgs = append([]string{b.ufwPath}, args...)
		return exec.Command("sudo", cmdArgs...)
	}
	return exec.Command(b.ufwPath, args...)
}

func (b *ufwBackend) run(args ...string) error {
	cmd := b.command(args...)
	cmd.Env = append(cmd.Env, "LC_ALL=C", "LANG=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return newCommandFailed("ufw", args, string(out), exitErr.ExitCode())
		}
		return &UfwError{Kind: ErrIO, Message: err.Error(), Err: err}
	}
	return nil
}

func (b *ufwBackend) output(args ...string) (string, error) {
	cmd := b.command(args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", newCommandFailed("ufw", args, string(exitErr.Stderr), exitErr.ExitCode())
		}
		return "", &UfwError{Kind: ErrIO, Message: err.Error(), Err: err}
	}
	return string(out), nil
}

func (b *ufwBackend) deleteRule(args ...string) (bool, error) {
	cmd := b.command(args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	deleted := strings.Contains(stdoutStr, "Rule deleted") || strings.Contains(stderrStr, "Rule deleted")
	notFound := strings.Contains(stdoutStr, "Could not delete non-existent rule") ||
		strings.Contains(stderrStr, "Could not delete non-existent rule")

	if deleted {
		return true, nil
	}
	if notFound {
		return false, nil
	}
	if err == nil {
		return false, newParseError("delete command succeeded but output did not contain expected message")
	}
	return false, newCommandFailed("ufw", args, stderrStr, exitCode(err))
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// --- Port rules ---

func (b *ufwBackend) AllowPort(port uint16, protocol Protocol, comment string) error {
	if protocol == Both {
		if err := b.AllowPort(port, TCP, comment); err != nil {
			return err
		}
		return b.AllowPort(port, UDP, comment)
	}
	args := []string{"allow", fmt.Sprintf("%d/%s", port, protocol)}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DenyPort(port uint16, protocol Protocol, comment string) error {
	if protocol == Both {
		if err := b.DenyPort(port, TCP, comment); err != nil {
			return err
		}
		return b.DenyPort(port, UDP, comment)
	}
	args := []string{"deny", fmt.Sprintf("%d/%s", port, protocol)}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DeletePort(port uint16, protocol Protocol) (bool, error) {
	if protocol == Both {
		tcpDel, err := b.DeletePort(port, TCP)
		if err != nil {
			return tcpDel, err
		}
		udpDel, err := b.DeletePort(port, UDP)
		if err != nil {
			return udpDel, err
		}
		return tcpDel || udpDel, nil
	}
	rule := fmt.Sprintf("%d/%s", port, protocol)
	allowDel, err := b.deleteRule("delete", "allow", rule)
	if err != nil {
		return false, err
	}
	if allowDel {
		return true, nil
	}
	return b.deleteRule("delete", "deny", rule)
}

// --- IP rules ---

func (b *ufwBackend) AllowIP(ip netip.Addr, direction Direction, comment string) error {
	args := []string{"allow", string(direction), ip.String()}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DenyIP(ip netip.Addr, direction Direction, comment string) error {
	args := []string{"deny", string(direction), ip.String()}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DeleteIP(ip netip.Addr, direction Direction) (bool, error) {
	allowDel, err := b.deleteRule("delete", "allow", string(direction), ip.String())
	if err != nil {
		return false, err
	}
	if allowDel {
		return true, nil
	}
	return b.deleteRule("delete", "deny", string(direction), ip.String())
}

// --- IP+Port rules ---

func (b *ufwBackend) AllowIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction, comment string) error {
	var args []string
	if direction == To {
		args = []string{"allow", "to", ip.String(), "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
	} else {
		args = []string{"allow", "from", ip.String(), "to", "any", "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
	}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DenyIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction, comment string) error {
	var args []string
	if direction == To {
		args = []string{"deny", "to", ip.String(), "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
	} else {
		args = []string{"deny", "from", ip.String(), "to", "any", "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
	}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DeleteIPPort(ip netip.Addr, port uint16, protocol Protocol, direction Direction) (bool, error) {
	var allowArgs, denyArgs []string
	if direction == To {
		allowArgs = []string{"delete", "allow", "to", ip.String(), "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
		denyArgs = []string{"delete", "deny", "to", ip.String(), "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
	} else {
		allowArgs = []string{"delete", "allow", "from", ip.String(), "to", "any", "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
		denyArgs = []string{"delete", "deny", "from", ip.String(), "to", "any", "port", fmt.Sprintf("%d", port), "proto", string(protocol)}
	}
	allowDel, err := b.deleteRule(allowArgs...)
	if err != nil {
		return false, err
	}
	if allowDel {
		return true, nil
	}
	return b.deleteRule(denyArgs...)
}

// --- IP Range rules ---

func (b *ufwBackend) AllowIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	args := []string{"allow", string(direction), cidr.String()}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DenyIPRange(cidr netip.Prefix, direction Direction, comment string) error {
	args := []string{"deny", string(direction), cidr.String()}
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return b.run(args...)
}

func (b *ufwBackend) DeleteIPRange(cidr netip.Prefix, direction Direction) (bool, error) {
	allowDel, err := b.deleteRule("delete", "allow", string(direction), cidr.String())
	if err != nil {
		return false, err
	}
	if allowDel {
		return true, nil
	}
	return b.deleteRule("delete", "deny", string(direction), cidr.String())
}

// --- Status queries ---

func (b *ufwBackend) GetPortStatus(port uint16, protocol Protocol) (Status, error) {
	rules, err := b.ListAllRules()
	if err != nil {
		return StatusNone, err
	}
	result := StatusNone
	for _, r := range rules {
		if r.Kind == RuleKindPort && r.Port == port {
			if protocol == Both || r.Protocol == protocol {
				if r.Status == StatusAllowed {
					result = StatusAllowed
				} else if r.Status == StatusDenied {
					return StatusDenied, nil
				}
			}
		}
	}
	return result, nil
}

func (b *ufwBackend) GetIPStatus(ip netip.Addr, direction Direction) (Status, error) {
	rules, err := b.ListAllRules()
	if err != nil {
		return StatusNone, err
	}
	for _, r := range rules {
		if r.Kind == RuleKindIP && r.IP == ip && r.Direction == direction {
			return r.Status, nil
		}
	}
	return StatusNone, nil
}

func (b *ufwBackend) GetIPPortStatus(ip netip.Addr, port uint16, protocol Protocol, direction Direction) (Status, error) {
	rules, err := b.ListAllRules()
	if err != nil {
		return StatusNone, err
	}
	for _, r := range rules {
		if r.Kind == RuleKindIPPort && r.IP == ip && r.Port == port && r.Protocol == protocol && r.Direction == direction {
			return r.Status, nil
		}
	}
	return StatusNone, nil
}

func (b *ufwBackend) GetIPRangeStatus(cidr netip.Prefix, direction Direction) (Status, error) {
	rules, err := b.ListAllRules()
	if err != nil {
		return StatusNone, err
	}
	for _, r := range rules {
		if r.Kind == RuleKindIPRange && r.Prefix == cidr && r.Direction == direction {
			return r.Status, nil
		}
	}
	return StatusNone, nil
}

// --- Listing ---

func (b *ufwBackend) ListAllRules() ([]Rule, error) {
	raw, err := b.output("status", "numbered")
	if err != nil {
		return nil, err
	}
	return parseRules(raw)
}

func (b *ufwBackend) ListRules(filter RuleFilter) ([]Rule, error) {
	all, err := b.ListAllRules()
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

func (b *ufwBackend) ListAllowedPorts() ([]uint16, error) {
	rules, err := b.ListRules(RuleFilter{Action: Ptr(Allow), Kind: Ptr(RuleKindPort)})
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

func (b *ufwBackend) ListDeniedPorts() ([]uint16, error) {
	rules, err := b.ListRules(RuleFilter{Action: Ptr(Deny), Kind: Ptr(RuleKindPort)})
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

func (b *ufwBackend) ListAllowedIPs(direction Direction) ([]netip.Addr, error) {
	rules, err := b.ListRules(RuleFilter{Action: Ptr(Allow), Kind: Ptr(RuleKindIP), Direction: Ptr(direction)})
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

func (b *ufwBackend) ListDeniedIPs(direction Direction) ([]netip.Addr, error) {
	rules, err := b.ListRules(RuleFilter{Action: Ptr(Deny), Kind: Ptr(RuleKindIP), Direction: Ptr(direction)})
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

func (b *ufwBackend) ListAllowedIPRanges(direction Direction) ([]netip.Prefix, error) {
	rules, err := b.ListRules(RuleFilter{Action: Ptr(Allow), Kind: Ptr(RuleKindIPRange), Direction: Ptr(direction)})
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

func (b *ufwBackend) ListDeniedIPRanges(direction Direction) ([]netip.Prefix, error) {
	rules, err := b.ListRules(RuleFilter{Action: Ptr(Deny), Kind: Ptr(RuleKindIPRange), Direction: Ptr(direction)})
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

func (b *ufwBackend) Enable() error {
	return b.run("--force", "enable")
}

func (b *ufwBackend) Disable() error {
	return b.run("disable")
}

func (b *ufwBackend) Reload() error {
	return b.run("reload")
}

func (b *ufwBackend) Reset() error {
	return b.run("--force", "reset")
}

func (b *ufwBackend) Flush() error {
	return b.Reset()
}

func (b *ufwBackend) IsInstalled() (bool, error) {
	_, err := exec.LookPath("ufw")
	return err == nil, nil
}

func (b *ufwBackend) IsEnabled() (bool, error) {
	raw, err := b.output("status")
	if err != nil {
		return false, err
	}
	return parseIsEnabled(raw)
}

func (b *ufwBackend) RawStatus() (string, error) {
	return b.output("status")
}

func (b *ufwBackend) DefaultDenyIncoming() error {
	return b.run("default", "deny", "incoming")
}

func (b *ufwBackend) DefaultAllowOutgoing() error {
	return b.run("default", "allow", "outgoing")
}

// --- Filter matching ---

func matchRuleFilter(rule Rule, filter RuleFilter) bool {
	if filter.Action != nil && rule.Action != *filter.Action {
		return false
	}
	if filter.Status != nil && rule.Status != *filter.Status {
		return false
	}
	if filter.Kind != nil && rule.Kind != *filter.Kind {
		return false
	}
	if filter.Protocol != nil && rule.Protocol != *filter.Protocol {
		return false
	}
	if filter.Direction != nil && rule.Direction != *filter.Direction {
		return false
	}
	if filter.Port != nil && rule.Port != *filter.Port {
		return false
	}
	if filter.IP != nil && rule.IP != *filter.IP {
		return false
	}
	if filter.IPRange != nil && rule.Prefix != *filter.IPRange {
		return false
	}
	if filter.Comment != "" && !strings.Contains(rule.Comment, filter.Comment) {
		return false
	}
	return true
}
