package goufw

// Status represents a rule's current state after querying.
type Status string

const (
	StatusAllowed Status = "allowed" // Traffic is allowed by this rule
	StatusDenied  Status = "denied"  // Traffic is denied by this rule
	StatusNone    Status = "none"    // No matching rule exists
)
