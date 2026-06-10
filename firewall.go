package goufw

import (
	"net"
	"os/exec"
)

type Firewall struct{}

func New() *Firewall {
	return &Firewall{}
}

func (fw *Firewall) IsInstalled() (bool, error) {
	err := exec.Command("ufw", "--help").Run()
	return err == nil, nil
}

func (fw *Firewall) IsEnabled() (bool, error) {
	raw, err := runner.output("sudo", "ufw", "status")
	if err != nil {
		return false, err
	}
	return parseIsEnabled(raw)
}

func (fw *Firewall) Enable() error {
	return runner.run("sudo", "ufw", "--force", "enable")
}

func (fw *Firewall) Disable() error {
	return runner.run("sudo", "ufw", "disable")
}

func (fw *Firewall) Reload() error {
	return runner.run("sudo", "ufw", "reload")
}

func (fw *Firewall) Reset() error {
	return runner.run("sudo", "ufw", "--force", "reset")
}

func (fw *Firewall) DefaultDenyIncoming() error {
	return runner.run("sudo", "ufw", "default", "deny", "incoming")
}

func (fw *Firewall) DefaultAllowOutgoing() error {
	return runner.run("sudo", "ufw", "default", "allow", "outgoing")
}

func (fw *Firewall) RawStatus() (string, error) {
	return runner.output("sudo", "ufw", "status")
}

func (fw *Firewall) Port(port uint16) *PortBuilder {
	return &PortBuilder{fw: fw, port: port}
}

func (fw *Firewall) IPv4(ip string) (*IPv4Builder, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil, newInvalidIPv4(ip)
	}
	return &IPv4Builder{fw: fw, ip: parsed}, nil
}

func (fw *Firewall) IPv6(ip string) (*IPv6Builder, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return nil, newInvalidIPv6(ip)
	}
	return &IPv6Builder{fw: fw, ip: parsed}, nil
}

func (fw *Firewall) Ports() ([]PortRule, error) {
	raw, err := runner.output("sudo", "ufw", "status", "numbered")
	if err != nil {
		return nil, err
	}
	return parsePortRules(raw)
}

func (fw *Firewall) IPs() ([]IpRule, error) {
	raw, err := runner.output("sudo", "ufw", "status", "numbered")
	if err != nil {
		return nil, err
	}
	return parseIPRules(raw)
}
