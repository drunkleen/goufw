package goufw

// Direction specifies the traffic flow relative to this host.
type Direction string

const (
	From Direction = "from" // Source IP or network
	To   Direction = "to"   // Destination IP or network
)
