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

```go
package main

import (
    "fmt"
    "github.com/drunkleen/goufw"
)

func main() {
    fw := goufw.New()

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
    fmt.Println(status)
}
```

### IPv4 rules

```go
fw.IPv4("192.168.1.10").Allow().Both().Apply()
fw.IPv4("192.168.1.10").Deny().TCP().Apply()
deleted, _ := fw.IPv4("192.168.1.10").Delete().Both().Apply()
status, _ := fw.IPv4("192.168.1.10").Status().TCP()
```

### IPv6 rules

```go
fw.IPv6("::1").Allow().Both().Apply()
fw.IPv6("::1").Deny().TCP().Apply()
deleted, _ := fw.IPv6("::1").Delete().Both().Apply()
status, _ := fw.IPv6("::1").Status().TCP()
```

### Error handling

```go
if err := fw.Enable(); err != nil {
    log.Fatalf("failed: %v", err)
}
```

## Safety note

This library modifies firewall rules by running `sudo ufw ...` commands. Depending on your
configuration, this may require root privileges or passwordless sudo for the `ufw` command.
Use with caution in production environments.
