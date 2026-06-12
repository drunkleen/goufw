package goufw

// Protocol specifies a transport protocol for firewall rules.
type Protocol string

const (
	TCP  Protocol = "tcp"  // TCP protocol
	UDP  Protocol = "udp"  // UDP protocol
	Both Protocol = "both" // Both TCP and UDP
)
