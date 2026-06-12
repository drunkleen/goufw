# goufw

A Go library for managing UFW firewall rules through the official `ufw` CLI.
Mirrors the API style of [gofw](https://github.com/drunkleen/gofw) but uses UFW
as the backend instead of nftables.

> **WARNING**: This library modifies firewall rules by running `sudo ufw ...`
> commands. Use carefully on remote servers to avoid locking yourself out.

## Installation

```bash
go get github.com/drunkleen/goufw
```

## Quick Start

```go
package main

import (
    "log"
    "net/netip"

    "github.com/drunkleen/goufw"
)

func main() {
    fw, err := goufw.New()
    if err != nil {
        log.Fatal(err)
    }

    // Allow SSH
    if err := fw.AllowPort(22, goufw.TCP, "SSH"); err != nil {
        log.Fatal(err)
    }

    // Deny Telnet
    if err := fw.DenyPort(23, goufw.TCP, "Block Telnet"); err != nil {
        log.Fatal(err)
    }

    // Allow an IP
    ip := netip.MustParseAddr("192.168.1.10")
    if err := fw.AllowIP(ip, goufw.From, "Trusted source"); err != nil {
        log.Fatal(err)
    }

    // Block a subnet
    cidr := netip.MustParsePrefix("10.0.0.0/8")
    if err := fw.BlockIPRange(cidr, goufw.To, "Blocked subnet"); err != nil {
        log.Fatal(err)
    }
}
```

## Mock Backend

For testing and development without root privileges or UFW installed:

```go
fw, _ := goufw.NewWithConfig(goufw.Config{Backend: goufw.BackendMock})
```

## API Overview

### Port Rules

```go
fw.AllowPort(22, goufw.TCP, "SSH")
fw.DenyPort(23, goufw.TCP, "Block Telnet")
fw.DeletePort(22, goufw.TCP)               // idempotent, returns nil if not found
```

### IP Rules

```go
ip := netip.MustParseAddr("192.168.1.10")
fw.AllowIP(ip, goufw.From, "Trusted source")
fw.DenyIP(ip, goufw.From, "Blocked host")
fw.DeleteIP(ip, goufw.From)
```

### IP+Port Rules

```go
ip := netip.MustParseAddr("10.0.0.1")
fw.AllowIPPort(ip, 22, goufw.TCP, goufw.From, "SSH from trusted")
fw.DenyIPPort(ip, 3306, goufw.TCP, goufw.From, "Block MySQL")
fw.DeleteIPPort(ip, 22, goufw.TCP, goufw.From)
```

### IP Range Rules

```go
cidr := netip.MustParsePrefix("192.168.1.0/24")
fw.AllowIPRange(cidr, goufw.From, "LAN")
fw.DenyIPRange(cidr, goufw.From, "Blocked subnet")
fw.BlockIPRange(cidr, goufw.To, "Alias for DenyIPRange") // calls DenyIPRange
fw.DeleteIPRange(cidr, goufw.From)
```

### Status Queries

```go
status, _ := fw.GetPortStatus(22, goufw.TCP)
// Returns StatusAllowed, StatusDenied, or StatusNone

status, _ = fw.GetIPStatus(ip, goufw.From)
status, _ = fw.GetIPPortStatus(ip, 22, goufw.TCP, goufw.From)
status, _ = fw.GetIPRangeStatus(cidr, goufw.From)
```

### Listing Rules

```go
rules, _ := fw.ListAllRules()
for _, rule := range rules {
    fmt.Printf("kind=%-8s action=%-5s proto=%-4s port=%-5d ip=%-15s comment=%s\n",
        rule.Kind, rule.Action, rule.Protocol, rule.Port, rule.IP, rule.Comment)
}

tcpRules, _ := fw.ListRules(goufw.RuleFilter{Protocol: goufw.Ptr(goufw.TCP)})

ports, _ := fw.ListAllowedPorts()
ports, _ = fw.ListDeniedPorts()

ips, _ := fw.ListAllowedIPs(goufw.From)
ips, _ = fw.ListDeniedIPs(goufw.To)

ranges, _ := fw.ListAllowedIPRanges(goufw.From)
ranges, _ = fw.ListDeniedIPRanges(goufw.To)
```

### Management

```go
fw.Enable()
fw.Disable()
fw.Reload()
fw.Reset()
fw.Flush()                          // alias for Reset
fw.DefaultDenyIncoming()
fw.DefaultAllowOutgoing()

installed, _ := fw.IsInstalled()
enabled, _ := fw.IsEnabled()
raw, _ := fw.RawStatus()
```

## Difference from gofw

| Aspect | gofw | goufw |
|--------|------|-------|
| Backend | nftables (direct netlink) | UFW CLI (`sudo ufw`) |
| Dependencies | `github.com/google/nftables` | Zero (stdlib only) |
| Root required | For nftables operations | For `sudo ufw` |
| Constructor | `New() (Firewall, error)` | `New() (*Firewall, error)` |
| Mock backend | `BackendMock` | `BackendMock` |
| Protocol type | `Protocol` (string) | `Protocol` (string) |
| Rule comment support | Native via nftables userdata | Via UFW `comment` flag |
| Delete idempotency | Returns `ErrRuleNotFound` | Returns `nil` (idempotent) |
| Rule listing | Queries nftables directly | Parses `ufw status numbered` |

## UFW Backend Notes

- `goufw` communicates with UFW exclusively through the `ufw` CLI. It never
  reads or writes `/etc/ufw/*` directly.
- Commands are executed with `LC_ALL=C` and `LANG=C` to ensure parseable output.
- Comments in `ufw status numbered` output may not be available in all UFW
  versions. The parser attempts to extract them from `#` suffixes.
- `Flush()` calls `ufw --force reset`, which removes all UFW rules including
  those not added by goufw.
- IPv4 and IPv6 are both supported via `net/netip`.
- The `Both` protocol runs separate `ufw allow/deny` commands for TCP and UDP.

## Types

```go
type Action string        // Allow, Deny
type Protocol string      // TCP, UDP, Both
type Status string        // StatusAllowed, StatusDenied, StatusNone
type Direction string     // From, To
type RuleKind string      // RuleKindPort, RuleKindIP, RuleKindIPPort, RuleKindIPRange

type Rule struct {
    Kind      RuleKind
    Action    Action
    Status    Status
    Protocol  Protocol
    Port      uint16
    IP        netip.Addr
    Prefix    netip.Prefix
    Direction Direction
    Comment   string
    Raw       string
}

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

type Config struct {
    Backend Backend   // BackendUFW or BackendMock
}
```

## Error Handling

Sentinel errors for common failure modes:

```go
var (
    ErrInvalidPort      = errors.New("invalid port")
    ErrInvalidProtocol  = errors.New("invalid protocol")
    ErrInvalidDirection = errors.New("invalid direction")
    ErrInvalidIP        = errors.New("invalid IP")
    ErrInvalidPrefix    = errors.New("invalid prefix")
    ErrUFWNotFound      = errors.New("ufw not installed")
    ErrUnsupportedOp    = errors.New("unsupported operation")
)
```

`*UfwError` is returned when a UFW command fails:

```go
if err := fw.Enable(); err != nil {
    var ue *goufw.UfwError
    if errors.As(err, &ue) {
        log.Printf("command %s failed with code %d", ue.Program, ue.Code)
    }
}
```

## Builder API (Legacy)

The original builder chain API still compiles and works:

```go
fw.Port(22).Allow().TCP().Apply()
fw.Port(8080).Deny().UDP().Apply()
deleted, _ := fw.Port(22).Delete().TCP().Apply()
status, _ := fw.Port(22).Status().TCP()
```

This API is preserved for backward compatibility. New code should prefer the
gofw-like direct methods.

## Testing

```bash
# Unit tests with mock backend (no root required)
go test ./...

# With race detector
go test -race ./...

# Vet
go vet ./...
```

## License

MIT
