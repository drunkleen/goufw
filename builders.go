package goufw

import "fmt"

// ---------------------------------------------------------------------------
// PortBuilder
// ---------------------------------------------------------------------------

type PortBuilder struct {
	fw   *Firewall
	port uint16
}

func (b *PortBuilder) Allow() *PortActionBuilder {
	return &PortActionBuilder{fw: b.fw, port: b.port, action: actionAllow}
}

func (b *PortBuilder) Deny() *PortActionBuilder {
	return &PortActionBuilder{fw: b.fw, port: b.port, action: actionDeny}
}

func (b *PortBuilder) Delete() *PortDeleteBuilder {
	return &PortDeleteBuilder{port: b.port}
}

func (b *PortBuilder) Status() *PortStatus {
	return &PortStatus{fw: b.fw, port: b.port}
}

// ---------------------------------------------------------------------------
// PortActionBuilder — allow / deny
// ---------------------------------------------------------------------------

type PortActionBuilder struct {
	fw     *Firewall
	port   uint16
	action action
}

func (b *PortActionBuilder) TCP() *PortFinalizer {
	return &PortFinalizer{fw: b.fw, port: b.port, action: b.action, protocol: ProtocolTCP}
}

func (b *PortActionBuilder) UDP() *PortFinalizer {
	return &PortFinalizer{fw: b.fw, port: b.port, action: b.action, protocol: ProtocolUDP}
}

func (b *PortActionBuilder) Both() *PortFinalizer {
	return &PortFinalizer{fw: b.fw, port: b.port, action: b.action, protocol: ProtocolBoth}
}

type PortFinalizer struct {
	fw       *Firewall
	port     uint16
	action   action
	protocol Protocol
}

func (f *PortFinalizer) Apply() error {
	protocols := protoStrings(f.protocol)
	actionStr := actionString(f.action)
	var runner commandRunner
	for _, proto := range protocols {
		rule := fmt.Sprintf("%d/%s", f.port, proto)
		if err := runner.run("sudo", "ufw", actionStr, rule); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// PortDeleteBuilder
// ---------------------------------------------------------------------------

type PortDeleteBuilder struct {
	port uint16
}

func (b *PortDeleteBuilder) TCP() *PortDeleteFinalizer {
	return &PortDeleteFinalizer{port: b.port, protocol: ProtocolTCP}
}

func (b *PortDeleteBuilder) UDP() *PortDeleteFinalizer {
	return &PortDeleteFinalizer{port: b.port, protocol: ProtocolUDP}
}

func (b *PortDeleteBuilder) Both() *PortDeleteFinalizer {
	return &PortDeleteFinalizer{port: b.port, protocol: ProtocolBoth}
}

type PortDeleteFinalizer struct {
	port     uint16
	protocol Protocol
}

func (f *PortDeleteFinalizer) Apply() (bool, error) {
	var results []deleteResult

	switch f.protocol {
	case ProtocolTCP:
		results = append(results,
			deleteResultOf("sudo", "ufw", "delete", "allow", fmt.Sprintf("%d/tcp", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "deny", fmt.Sprintf("%d/tcp", f.port)),
		)
	case ProtocolUDP:
		results = append(results,
			deleteResultOf("sudo", "ufw", "delete", "allow", fmt.Sprintf("%d/udp", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "deny", fmt.Sprintf("%d/udp", f.port)),
		)
	case ProtocolBoth:
		results = append(results,
			deleteResultOf("sudo", "ufw", "delete", "allow", fmt.Sprintf("%d", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "deny", fmt.Sprintf("%d", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "allow", fmt.Sprintf("%d/tcp", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "deny", fmt.Sprintf("%d/tcp", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "allow", fmt.Sprintf("%d/udp", f.port)),
			deleteResultOf("sudo", "ufw", "delete", "deny", fmt.Sprintf("%d/udp", f.port)),
		)
	}
	return combineDeleteOutcomes(results)
}

// ---------------------------------------------------------------------------
// PortStatus
// ---------------------------------------------------------------------------

type PortStatus struct {
	fw   *Firewall
	port uint16
}

func (s *PortStatus) TCP() (RuleStatus, error) {
	rules, err := s.fw.Ports()
	if err != nil {
		return RuleStatusNone, err
	}
	return findPortStatus(rules, s.port, ProtocolTCP), nil
}

func (s *PortStatus) UDP() (RuleStatus, error) {
	rules, err := s.fw.Ports()
	if err != nil {
		return RuleStatusNone, err
	}
	return findPortStatus(rules, s.port, ProtocolUDP), nil
}

func (s *PortStatus) Both() (RuleStatus, error) {
	rules, err := s.fw.Ports()
	if err != nil {
		return RuleStatusNone, err
	}
	return findPortStatus(rules, s.port, ProtocolBoth), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func protoStrings(p Protocol) []string {
	switch p {
	case ProtocolTCP:
		return []string{"tcp"}
	case ProtocolUDP:
		return []string{"udp"}
	case ProtocolBoth:
		return []string{"tcp", "udp"}
	}
	return nil
}

func actionString(a action) string {
	switch a {
	case actionAllow:
		return "allow"
	case actionDeny:
		return "deny"
	}
	return ""
}
