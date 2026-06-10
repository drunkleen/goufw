package goufw

// These tests verify that the builder chains compile correctly.
// They do not execute real UFW commands.

func ExampleFirewall_Port_allow() {
	fw := New()
	_ = fw.Port(22).Allow().TCP()
	_ = fw.Port(22).Allow().UDP()
	_ = fw.Port(22).Allow().Both()
	_ = fw.Port(22).Deny().TCP()
	_ = fw.Port(22).Deny().Both()
	_ = fw.Port(22).Delete().TCP()
	_ = fw.Port(22).Delete().UDP()
	_ = fw.Port(22).Delete().Both()
	_ = fw.Port(22).Status()
}

func ExampleFirewall_IPv4_allow() {
	fw := New()
	b, _ := fw.IPv4("192.168.1.10")
	_ = b.Allow().TCP()
	_ = b.Allow().UDP()
	_ = b.Allow().Both()
	_ = b.Deny().TCP()
	_ = b.Deny().Both()
	_ = b.Delete().Both()
	_ = b.Status()
}

func ExampleFirewall_IPv6_allow() {
	fw := New()
	b, _ := fw.IPv6("::1")
	_ = b.Allow().TCP()
	_ = b.Allow().UDP()
	_ = b.Allow().Both()
	_ = b.Deny().TCP()
	_ = b.Deny().Both()
	_ = b.Delete().Both()
	_ = b.Status()
}
