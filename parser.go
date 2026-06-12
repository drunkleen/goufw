package goufw

import (
	"net/netip"
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

func parseRules(raw string) ([]Rule, error) {
	var rules []Rule
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
		if r := parseRuleLine(content); r != nil {
			rules = append(rules, *r)
		}
	}
	return rules, nil
}

func parseRuleLine(content string) *Rule {
	actionStr, actionStart := findAction(content)
	if actionStr == "" {
		return nil
	}

	target := strings.TrimSpace(content[:actionStart])
	rest := strings.TrimSpace(content[actionStart+len(actionStr):])

	var comment string
	if idx := strings.Index(rest, "#"); idx >= 0 {
		comment = strings.TrimSpace(rest[idx+1:])
		rest = strings.TrimSpace(rest[:idx])
	}

	var act Action
	var dir Direction
	switch actionStr {
	case "ALLOW IN":
		act = Allow
		dir = From
	case "ALLOW OUT":
		act = Allow
		dir = To
	case "DENY IN":
		act = Deny
		dir = From
	case "DENY OUT":
		act = Deny
		dir = To
	default:
		return nil
	}

	target = strings.TrimSuffix(strings.TrimSpace(target), "(v6)")
	target = strings.TrimSpace(target)
	rest = strings.TrimSuffix(strings.TrimSpace(rest), "(v6)")
	rest = strings.TrimSpace(rest)

	if strings.Contains(target, "/") {
		// Extract port/proto from the last token if target has spaces
		// (e.g. "172.17.0.1 53/udp" → portProto="53/udp", ipPart="172.17.0.1")
		portProto := target
		var ipPart string
		if fields := strings.Fields(target); len(fields) >= 2 {
			portProto = fields[len(fields)-1]
			ipPart = strings.TrimSpace(strings.Join(fields[:len(fields)-1], " "))
			ipPart = strings.TrimSuffix(ipPart, "(v6)")
			ipPart = strings.TrimSpace(ipPart)
		}

		parts := strings.SplitN(portProto, "/", 2)
		port, err := strconv.ParseUint(parts[0], 10, 16)
		if err == nil {
			var proto Protocol
			switch parts[1] {
			case "tcp":
				proto = TCP
			case "udp":
				proto = UDP
			default:
				return nil
			}

			// If target had an IP before port/proto, it's an IPPort rule
			if ipPart != "" {
				if ipAddr, err := netip.ParseAddr(ipPart); err == nil {
					return &Rule{
						Kind:      RuleKindIPPort,
						Action:    act,
						Status:    actionToStatus(act),
						Protocol:  proto,
						Port:      uint16(port),
						IP:        ipAddr,
						Direction: dir,
						Comment:   comment,
						Raw:       content,
					}
				}
			}

			// Check if rest is an IP (source for From, dest for To)
			if sourceIP, err := netip.ParseAddr(rest); err == nil {
				return &Rule{
					Kind:      RuleKindIPPort,
					Action:    act,
					Status:    actionToStatus(act),
					Protocol:  proto,
					Port:      uint16(port),
					IP:        sourceIP,
					Direction: dir,
					Comment:   comment,
					Raw:       content,
				}
			}

			return &Rule{
				Kind:      RuleKindPort,
				Action:    act,
				Status:    actionToStatus(act),
				Protocol:  proto,
				Port:      uint16(port),
				Direction: dir,
				Comment:   comment,
				Raw:       content,
			}
		}

		if prefix, err := netip.ParsePrefix(target); err == nil {
			return &Rule{
				Kind:      RuleKindIPRange,
				Action:    act,
				Status:    actionToStatus(act),
				Prefix:    prefix,
				Direction: To,
				Comment:   comment,
				Raw:       content,
			}
		}

		if sourcePrefix, err := netip.ParsePrefix(rest); err == nil {
			return &Rule{
				Kind:      RuleKindIPRange,
				Action:    act,
				Status:    actionToStatus(act),
				Prefix:    sourcePrefix,
				Direction: dir,
				Comment:   comment,
				Raw:       content,
			}
		}
	}

	if targetIP, err := netip.ParseAddr(target); err == nil {
		return &Rule{
			Kind:      RuleKindIP,
			Action:    act,
			Status:    actionToStatus(act),
			IP:        targetIP,
			Direction: To,
			Comment:   comment,
			Raw:       content,
		}
	}

	if target == "Anywhere" || target == "0.0.0.0/0" || target == "::/0" {
		if sourceIP, err := netip.ParseAddr(rest); err == nil {
			return &Rule{
				Kind:      RuleKindIP,
				Action:    act,
				Status:    actionToStatus(act),
				IP:        sourceIP,
				Direction: dir,
				Comment:   comment,
				Raw:       content,
			}
		}
		if sourcePrefix, err := netip.ParsePrefix(rest); err == nil {
			return &Rule{
				Kind:      RuleKindIPRange,
				Action:    act,
				Status:    actionToStatus(act),
				Prefix:    sourcePrefix,
				Direction: dir,
				Comment:   comment,
				Raw:       content,
			}
		}
	}

	return nil
}

func findAction(content string) (string, int) {
	actions := []string{"ALLOW IN", "ALLOW OUT", "DENY IN", "DENY OUT"}
	for _, a := range actions {
		if pos := strings.Index(content, a); pos >= 0 {
			return a, pos
		}
	}
	return "", -1
}

func actionToStatus(a Action) Status {
	switch a {
	case Allow:
		return StatusAllowed
	case Deny:
		return StatusDenied
	}
	return StatusNone
}
