package goufw

import "fmt"

type RuleStatus int

const (
	RuleStatusAllowed RuleStatus = iota
	RuleStatusDenied
	RuleStatusNone
)

func (s RuleStatus) String() string {
	switch s {
	case RuleStatusAllowed:
		return "Allowed"
	case RuleStatusDenied:
		return "Denied"
	case RuleStatusNone:
		return "None"
	}
	return fmt.Sprintf("RuleStatus(%d)", int(s))
}
