# goufw

Go library for managing UFW firewall rules through the official `ufw` CLI.

```
go get github.com/drunkleen/goufw@v0.1.0
```

## Linux-only

This package targets Linux exclusively because UFW is a Linux-specific tool.

## No external dependencies

Zero external dependencies. Uses only the Go standard library (`os/exec`, `net`, etc.).

## UFW CLI wrapper

`goufw` wraps the `ufw` command-line tool via `os/exec`. It does not read or write
`/etc/ufw/*` files directly. Every operation delegates to the `ufw` binary.

## Why no install / uninstall?

Package management (apt, pacman, dnf, etc.) is distro-specific and outside the scope of a
core firewall library. Use your system package manager to install or remove `ufw` itself.

## Usage

### Firewall management

```go
fw := goufw.New()

fw.Enable()                              // enable UFW
fw.Disable()                             // disable UFW
fw.Reload()                              // reload UFW
fw.Reset()                               // reset UFW to defaults
fw.DefaultDenyIncoming()                 // set default policy: deny incoming
fw.DefaultAllowOutgoing()                // set default policy: allow outgoing

installed, _ := fw.IsInstalled()         // check if ufw binary exists
enabled, _ := fw.IsEnabled()             // check if UFW is active
raw, _ := fw.RawStatus()                 // raw ufw status output
```

### Port rules

```go
// Allow TCP on port 22
fw.Port(22).Allow().TCP().Apply()

// Deny UDP on port 8080
fw.Port(8080).Deny().UDP().Apply()

// Allow both TCP and UDP on port 5050
fw.Port(5050).Allow().Both().Apply()

// Delete a rule (idempotent)
deleted, _ := fw.Port(5050).Delete().Both().Apply()
if deleted {
    fmt.Println("Rule deleted")
} else {
    fmt.Println("Rule did not exist")
}

// Check status
status, _ := fw.Port(22).Status().TCP()
fmt.Println(status) // Allowed, Denied, or None
```

### IPv4 rules

```go
b, err := fw.IPv4("192.168.1.10")
// err is non-nil for invalid addresses

b.Allow().Both().Apply()
b.Deny().TCP().Apply()
deleted, _ := b.Delete().Both().Apply()
status, _ := b.Status().TCP()
```

### IPv6 rules

```go
b, err := fw.IPv6("::1")
// err is non-nil for invalid addresses

b.Allow().Both().Apply()
b.Deny().TCP().Apply()
deleted, _ := b.Delete().Both().Apply()
status, _ := b.Status().TCP()
```

### Listing rules

```go
ports, _ := fw.Ports()  // []PortRule{Port, Protocol, Status}
ips, _ := fw.IPs()      // []IpRule{IP, Protocol, Status}
```

## Error handling

All methods that execute UFW commands return `*goufw.UfwError` on failure:

```go
if err := fw.Enable(); err != nil {
    var ue *goufw.UfwError
    if errors.As(err, &ue) {
        switch ue.Kind {
        case goufw.ErrCommandFailed:
            log.Printf("command %s %v exited with code %d", ue.Program, ue.Args, ue.Code)
        case goufw.ErrInvalidIPv4:
            log.Printf("bad IPv4: %s", ue.Message)
        }
    }
}
```

Error kinds: `ErrIO`, `ErrCommandFailed`, `ErrInvalidIPv4`, `ErrInvalidIPv6`, `ErrParse`, `ErrEmptyOutput`, `ErrUnexpectedStatusLine`.

## Rule status

```go
type RuleStatus int

const (
    RuleStatusAllowed RuleStatus = iota
    RuleStatusDenied
    RuleStatusNone
)
```

## Safety note

This library modifies firewall rules by running `sudo ufw ...` commands. Depending on your
configuration, this may require root privileges or passwordless sudo for the `ufw` command.
Use with caution in production environments.
