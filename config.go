package goufw

// Backend selects which firewall implementation to use.
type Backend string

const (
	BackendUFW  Backend = "ufw"  // Real UFW CLI (requires root/sudo)
	BackendMock Backend = "mock" // In-memory mock (for tests, no root)
)

// Config controls how a Firewall is created.
type Config struct {
	Backend Backend // Backend to use: BackendUFW or BackendMock
}

// DefaultConfig returns a Config with the UFW backend.
// Use NewWithConfig to override.
func DefaultConfig() Config {
	return Config{Backend: BackendUFW}
}
