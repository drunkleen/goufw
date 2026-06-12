package goufw

// Action specifies whether to allow or deny traffic.
type Action string

const (
	Allow Action = "allow" // Allow traffic
	Deny  Action = "deny"  // Deny traffic
)
