# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-06-12

### Breaking changes

- `New()` now returns `(*Firewall, error)` — checks UFW is installed.
- Renamed constants: `ProtocolTCP` → `TCP`, `ProtocolUDP` → `UDP`, `ProtocolBoth` → `Both`.
- Renamed `RuleStatus` → `Status`, `RuleStatusAllowed` → `StatusAllowed`, etc.
- Removed `Ports()` / `IPs()` methods — replaced by new list methods.
- Removed `PortRule` / `IpRule` types — replaced by unified `Rule` struct.

### Added

- gofw-like public API: `AllowPort`, `DenyPort`, `DeletePort`, `AllowIP`, `DenyIP`, `DeleteIP`,
  `AllowIPPort`, `DenyIPPort`, `DeleteIPPort`, `AllowIPRange`, `DenyIPRange`, `BlockIPRange`,
  `DeleteIPRange`, `GetPortStatus`, `GetIPStatus`, `GetIPPortStatus`, `GetIPRangeStatus`,
  `ListAllRules`, `ListRules`, `ListAllowedPorts`, `ListDeniedPorts`, `ListAllowedIPs`,
  `ListDeniedIPs`, `ListAllowedIPRanges`, `ListDeniedIPRanges`, `Flush`.
- `NewWithConfig(Config)` constructor with backend selection.
- `Config`, `Backend`, `Direction`, `RuleKind`, `RuleFilter` types.
- In-memory mock backend (`BackendMock`) for tests — no root/sudo required.
- Sentinel errors: `ErrInvalidPort`, `ErrInvalidProtocol`, `ErrInvalidDirection`,
  `ErrInvalidIP`, `ErrInvalidPrefix`, `ErrUFWNotFound`, `ErrUnsupportedOp`.
- Validation functions: `ValidatePort`, `ValidateProtocol`, `ValidateDirection`,
  `ValidateIP`, `ValidatePrefix`, `Ptr`, `RuleID`.
- `LC_ALL=C` / `LANG=C` forced on all UFW commands for parseable output.
- Parent environment inherited by UFW commands (fixes PATH/sudo issues).

### Fixed

- Parser now handles `"<IP> <port>/<proto>"` target format (e.g. Docker DNS rules) —
  was misclassified as CIDR range.
- IPPort UFW commands for `To` direction no longer emit invalid `to any` syntax.
- Legacy IP builder (`IPFinalizer.Apply`) preserves TCP/UDP protocol restriction.

### Tests

- 95 tests covering all public methods, validation, parser edge cases, mock backend.
- All tests use mock backend — no root required.
- Example tests with `// Output:` assertions run via `go test -run Example`.

---

## [0.1.0] - 2026-06-10

### Added

- Initial release of `goufw`.
- Linux-only support.
- Zero external dependencies.
- UFW CLI wrapper using `os/exec`.
- Fluent builder API for firewall rules.

### Firewall Management

- Enable, disable, reload, reset UFW.
- Check if UFW is installed or enabled.
- Set default deny incoming / allow outgoing policies.

### Port Rules

- Allow, deny, and delete TCP / UDP / Both ports.
- Query port rule status.
- List configured port rules.
- Idempotent delete returns `true` if a rule was removed, `false` if it did not exist.

### IP Rules

- Allow, deny, and delete IPv4 and IPv6 addresses.
- Protocol-specific IP rules (TCP / UDP / Both).
- Query IP rule status.

### Error Handling

- `UfwError` type with structured command-failure and validation errors.
- IPv4 and IPv6 address validation at builder creation.

### Testing

- 49 unit tests covering parser, command classification, and public API.
- No real UFW commands are executed in tests.

---

[0.1.0]: https://github.com/drunkleen/goufw/releases/tag/v0.1.0
