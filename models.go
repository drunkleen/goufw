package goufw

import "net/netip"

// RuleKind classifies the type of a firewall rule.
type RuleKind string

const (
	RuleKindPort    RuleKind = "port"     // Port-only rule, e.g. "allow 22/tcp"
	RuleKindIP      RuleKind = "ip"       // IP-only rule, e.g. "allow from 1.2.3.4"
	RuleKindIPPort  RuleKind = "ip_port"  // IP+port rule, e.g. "allow from 1.2.3.4 port 22"
	RuleKindIPRange RuleKind = "ip_range" // CIDR range rule, e.g. "allow from 10.0.0.0/8"
)

// Rule represents a single firewall rule returned by list/status queries.
// Zero-valued fields mean the field does not apply to this rule.
type Rule struct {
	Kind      RuleKind     // Kind of rule
	Action    Action       // Allow or Deny
	Status    Status       // Current status
	Protocol  Protocol     // TCP, UDP, or Both
	Port      uint16       // Port number (0 if not a port rule)
	IP        netip.Addr   // IP address (zero if not an IP rule)
	Prefix    netip.Prefix // CIDR prefix (zero if not a range rule)
	Direction Direction    // From (source) or To (destination)
	Comment   string       // Optional rule comment
	Raw       string       // Raw UFW status line
}

// RuleFilter filters rules when calling ListRules.
// Nil fields are ignored. Comment does substring matching.
type RuleFilter struct {
	Action    *Action
	Status    *Status
	Kind      *RuleKind
	Protocol  *Protocol
	Port      *uint16
	IP        *netip.Addr
	IPRange   *netip.Prefix
	Direction *Direction
	Comment   string
}
