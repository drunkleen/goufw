package goufw

import (
	"fmt"
	"net/netip"
)

func ExampleFirewall_AllowPort() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.AllowPort(22, TCP, "SSH")
	status, _ := fw.GetPortStatus(22, TCP)
	fmt.Println(status)
	// Output: allowed
}

func ExampleFirewall_DenyPort() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.DenyPort(23, TCP, "Telnet")
	status, _ := fw.GetPortStatus(23, TCP)
	fmt.Println(status)
	// Output: denied
}

func ExampleFirewall_DeletePort() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.AllowPort(22, TCP, "SSH")
	fw.DeletePort(22, TCP)
	status, _ := fw.GetPortStatus(22, TCP)
	fmt.Println(status)
	// Output: none
}

func ExampleFirewall_DeletePort_idempotent() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	err := fw.DeletePort(999, TCP)
	fmt.Println(err)
	// Output: <nil>
}

func ExampleFirewall_AllowIP() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})
	ip := netip.MustParseAddr("192.168.1.10")

	fw.AllowIP(ip, From, "Trusted source")
	status, _ := fw.GetIPStatus(ip, From)
	fmt.Println(status)
	// Output: allowed
}

func ExampleFirewall_DenyIP() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})
	ip := netip.MustParseAddr("10.0.0.5")

	fw.DenyIP(ip, To, "Blocked host")
	status, _ := fw.GetIPStatus(ip, To)
	fmt.Println(status)
	// Output: denied
}

func ExampleFirewall_AllowIPPort() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})
	ip := netip.MustParseAddr("10.0.0.1")

	fw.AllowIPPort(ip, 22, TCP, From, "SSH from trusted")
	status, _ := fw.GetIPPortStatus(ip, 22, TCP, From)
	fmt.Println(status)
	// Output: allowed
}

func ExampleFirewall_AllowIPRange() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})
	cidr := netip.MustParsePrefix("192.168.1.0/24")

	fw.AllowIPRange(cidr, From, "LAN")
	status, _ := fw.GetIPRangeStatus(cidr, From)
	fmt.Println(status)
	// Output: allowed
}

func ExampleFirewall_BlockIPRange() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})
	cidr := netip.MustParsePrefix("10.0.0.0/8")

	fw.BlockIPRange(cidr, To, "Blocked subnet")
	status, _ := fw.GetIPRangeStatus(cidr, To)
	fmt.Println(status)
	// Output: denied
}

func ExampleFirewall_ListAllRules() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.AllowPort(22, TCP, "SSH")
	fw.AllowPort(80, TCP, "HTTP")
	fw.DenyPort(23, TCP, "Telnet")

	rules, _ := fw.ListAllRules()
	fmt.Println(len(rules))
	// Output: 3
}

func ExampleFirewall_ListAllowedPorts() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.AllowPort(22, TCP, "SSH")
	fw.DenyPort(23, TCP, "Telnet")

	ports, _ := fw.ListAllowedPorts()
	fmt.Println(ports)
	// Output: [22]
}

func ExampleFirewall_Flush() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.AllowPort(22, TCP, "SSH")
	fw.AllowPort(80, TCP, "HTTP")
	fw.Flush()

	rules, _ := fw.ListAllRules()
	fmt.Println(len(rules))
	// Output: 0
}

func ExampleFirewall_Port_builder() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	fw.Port(22).Allow().TCP().Apply()
	status, _ := fw.Port(22).Status().TCP()
	fmt.Println(status)
	// Output: allowed
}

func ExampleIPv4Builder() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	b, _ := fw.IPv4("192.168.1.10")
	b.Allow().Both().Apply()
	status, _ := b.Status().Both()
	fmt.Println(status)
	// Output: allowed
}

func ExampleIPv6Builder() {
	fw, _ := NewWithConfig(Config{Backend: BackendMock})

	b, _ := fw.IPv6("::1")
	b.Allow().Both().Apply()
	status, _ := b.Status().Both()
	fmt.Println(status)
	// Output: allowed
}
