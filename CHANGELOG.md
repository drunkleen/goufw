# Changelog

All notable changes to this project will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
