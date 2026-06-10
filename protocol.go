package goufw

import "fmt"

type Protocol int

const (
	ProtocolTCP  Protocol = iota // "tcp"
	ProtocolUDP                  // "udp"
	ProtocolBoth                 // "both"
)

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolBoth:
		return "both"
	}
	return fmt.Sprintf("Protocol(%d)", int(p))
}

func (p Protocol) IsTCP() bool { return p == ProtocolTCP }

func (p Protocol) IsUDP() bool { return p == ProtocolUDP }
