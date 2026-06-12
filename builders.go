package goufw

// PortBuilder starts a port rule chain (legacy API).
//
//	fw.Port(22).Allow().TCP().Apply()
type PortBuilder struct {
	fw   *Firewall
	port uint16
}

// Allow starts an allow rule chain for this port.
func (b *PortBuilder) Allow() *PortActionBuilder {
	return &PortActionBuilder{fw: b.fw, port: b.port, action: Allow}
}

// Deny starts a deny rule chain for this port.
func (b *PortBuilder) Deny() *PortActionBuilder {
	return &PortActionBuilder{fw: b.fw, port: b.port, action: Deny}
}

// Delete starts a delete chain for this port.
//
//	deleted, _ := fw.Port(22).Delete().TCP().Apply()
func (b *PortBuilder) Delete() *PortDeleteBuilder {
	return &PortDeleteBuilder{fw: b.fw, port: b.port}
}

// Status starts a status query chain for this port.
//
//	status, _ := fw.Port(22).Status().TCP()
func (b *PortBuilder) Status() *PortStatus {
	return &PortStatus{fw: b.fw, port: b.port}
}

// PortActionBuilder selects the protocol for a port allow/deny rule.
type PortActionBuilder struct {
	fw     *Firewall
	port   uint16
	action Action
}

// TCP selects TCP protocol.
func (b *PortActionBuilder) TCP() *PortFinalizer {
	return &PortFinalizer{fw: b.fw, port: b.port, action: b.action, protocol: TCP}
}

// UDP selects UDP protocol.
func (b *PortActionBuilder) UDP() *PortFinalizer {
	return &PortFinalizer{fw: b.fw, port: b.port, action: b.action, protocol: UDP}
}

// Both selects both TCP and UDP protocols.
func (b *PortActionBuilder) Both() *PortFinalizer {
	return &PortFinalizer{fw: b.fw, port: b.port, action: b.action, protocol: Both}
}

// PortFinalizer applies a port allow/deny rule.
type PortFinalizer struct {
	fw       *Firewall
	port     uint16
	action   Action
	protocol Protocol
}

// Apply executes the port rule.
func (f *PortFinalizer) Apply() error {
	switch f.action {
	case Allow:
		return f.fw.AllowPort(f.port, f.protocol, "")
	case Deny:
		return f.fw.DenyPort(f.port, f.protocol, "")
	}
	return nil
}

// PortDeleteBuilder selects the protocol for a port delete operation.
type PortDeleteBuilder struct {
	fw   *Firewall
	port uint16
}

// TCP selects TCP protocol for delete.
func (b *PortDeleteBuilder) TCP() *PortDeleteFinalizer {
	return &PortDeleteFinalizer{fw: b.fw, port: b.port, protocol: TCP}
}

// UDP selects UDP protocol for delete.
func (b *PortDeleteBuilder) UDP() *PortDeleteFinalizer {
	return &PortDeleteFinalizer{fw: b.fw, port: b.port, protocol: UDP}
}

// Both selects both TCP and UDP for delete.
func (b *PortDeleteBuilder) Both() *PortDeleteFinalizer {
	return &PortDeleteFinalizer{fw: b.fw, port: b.port, protocol: Both}
}

// PortDeleteFinalizer runs a port delete.
type PortDeleteFinalizer struct {
	fw       *Firewall
	port     uint16
	protocol Protocol
}

// Apply executes the delete. Returns true if a rule was actually removed.
func (f *PortDeleteFinalizer) Apply() (bool, error) {
	return f.fw.backend.DeletePort(f.port, f.protocol)
}

// PortStatus queries the status of a port.
type PortStatus struct {
	fw   *Firewall
	port uint16
}

// TCP returns the status for TCP on this port.
func (s *PortStatus) TCP() (Status, error) {
	return s.fw.GetPortStatus(s.port, TCP)
}

// UDP returns the status for UDP on this port.
func (s *PortStatus) UDP() (Status, error) {
	return s.fw.GetPortStatus(s.port, UDP)
}

// Both returns the status for both TCP and UDP on this port.
func (s *PortStatus) Both() (Status, error) {
	return s.fw.GetPortStatus(s.port, Both)
}
