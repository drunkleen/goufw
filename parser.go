package goufw

import (
	"net"
	"strconv"
	"strings"
)

func parseIsEnabled(raw string) (bool, error) {
	line := raw
	if idx := strings.IndexByte(raw, '\n'); idx >= 0 {
		line = raw[:idx]
	}
	line = strings.TrimSpace(line)
	switch line {
	case "Status: active":
		return true, nil
	case "Status: inactive":
		return false, nil
	case "":
		return false, errEmptyOutput
	default:
		return false, newUnexpectedStatusLine(line)
	}
}

func parsePortRules(raw string) ([]PortRule, error) {
	var rules []PortRule
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") {
			continue
		}
		idx := strings.IndexByte(trimmed, ']')
		if idx < 0 {
			continue
		}
		content := strings.TrimSpace(trimmed[idx+1:])
		if r := parsePortRuleLine(content); r != nil {
			rules = append(rules, *r)
		}
	}
	return rules, nil
}

func parsePortRuleLine(content string) *PortRule {
	target, action := splitAtAction(content)
	if target == "" {
		return nil
	}
	target = strings.TrimSpace(target)
	fields := strings.Fields(target)
	if len(fields) == 0 {
		return nil
	}
	portProto := fields[0]
	portProto = strings.TrimSuffix(portProto, "(v6)")

	parts := strings.SplitN(portProto, "/", 2)
	if len(parts) != 2 {
		return nil
	}
	port, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil
	}
	var protocol Protocol
	switch parts[1] {
	case "tcp":
		protocol = ProtocolTCP
	case "udp":
		protocol = ProtocolUDP
	default:
		return nil
	}
	return &PortRule{
		Port:     uint16(port),
		Protocol: protocol,
		Status:   actionToStatus(action),
	}
}

func parseIPRules(raw string) ([]IpRule, error) {
	var rules []IpRule
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[") {
			continue
		}
		idx := strings.IndexByte(trimmed, ']')
		if idx < 0 {
			continue
		}
		content := strings.TrimSpace(trimmed[idx+1:])
		if r := parseIPRuleLine(content); r != nil {
			rules = append(rules, *r)
		}
	}
	return rules, nil
}

func parseIPRuleLine(content string) *IpRule {
	target, action := splitAtAction(content)
	if target == "" {
		return nil
	}
	target = strings.TrimSpace(target)
	if !strings.HasPrefix(target, "Anywhere") {
		return nil
	}
	var marker string
	switch action {
	case actionAllow:
		marker = "ALLOW IN"
	case actionDeny:
		marker = "DENY IN"
	}
	pos := strings.Index(content, marker)
	if pos < 0 {
		return nil
	}
	source := strings.TrimSpace(content[pos+len(marker):])
	source = strings.TrimSuffix(source, " (v6)")
	source = strings.TrimSpace(source)

	ip := net.ParseIP(source)
	if ip == nil {
		return nil
	}
	return &IpRule{
		IP:       ip,
		Protocol: ProtocolBoth,
		Status:   actionToStatus(action),
	}
}

func splitAtAction(content string) (string, action) {
	if pos := strings.Index(content, "ALLOW IN"); pos >= 0 {
		return content[:pos], actionAllow
	}
	if pos := strings.Index(content, "DENY IN"); pos >= 0 {
		return content[:pos], actionDeny
	}
	return "", 0
}

func actionToStatus(a action) RuleStatus {
	switch a {
	case actionAllow:
		return RuleStatusAllowed
	case actionDeny:
		return RuleStatusDenied
	}
	return RuleStatusNone
}

func findPortStatus(rules []PortRule, port uint16, protocol Protocol) RuleStatus {
	if protocol == ProtocolBoth {
		var tcpStatus, udpStatus *RuleStatus
		for _, r := range rules {
			if r.Port == port {
				if r.Protocol == ProtocolTCP {
					s := r.Status
					tcpStatus = &s
				} else if r.Protocol == ProtocolUDP {
					s := r.Status
					udpStatus = &s
				}
			}
		}
		if tcpStatus != nil && udpStatus != nil {
			if *tcpStatus == RuleStatusAllowed && *udpStatus == RuleStatusAllowed {
				return RuleStatusAllowed
			}
			if *tcpStatus == RuleStatusDenied && *udpStatus == RuleStatusDenied {
				return RuleStatusDenied
			}
			return RuleStatusNone
		}
		return RuleStatusNone
	}
	for _, r := range rules {
		if r.Port == port && r.Protocol == protocol {
			return r.Status
		}
	}
	return RuleStatusNone
}

func findIPStatus(rules []IpRule, ip net.IP, protocol Protocol) RuleStatus {
	for _, r := range rules {
		if r.IP.Equal(ip) {
			return r.Status
		}
	}
	return RuleStatusNone
}
