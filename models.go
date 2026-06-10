package goufw

import "net"

type PortRule struct {
	Port     uint16
	Protocol Protocol
	Status   RuleStatus
}

type IpRule struct {
	IP       net.IP
	Protocol Protocol
	Status   RuleStatus
}
