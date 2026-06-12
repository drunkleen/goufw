// Package goufw provides a Go API for managing UFW firewall rules through the
// official `ufw` CLI. It mirrors the API style of gofw but uses UFW as the
// backend instead of nftables.
//
// Usage:
//
//	fw, err := goufw.New()
//	if err != nil { ... }
//
//	fw.AllowPort(22, goufw.TCP, "SSH")
//	fw.DenyPort(23, goufw.TCP, "Block Telnet")
//
// See README for complete API documentation.
package goufw
