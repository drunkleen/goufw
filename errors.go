package goufw

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorKind classifies a UFW error for programmatic handling.
type ErrorKind int

const (
	ErrIO                   ErrorKind = iota // I/O or exec error
	ErrCommandFailed                         // UFW command returned non-zero exit
	ErrInvalidIPv4                           // Invalid IPv4 address string
	ErrInvalidIPv6                           // Invalid IPv6 address string
	ErrParse                                 // Failed to parse UFW output
	ErrEmptyOutput                           // UFW returned empty output
	ErrUnexpectedStatusLine                  // Unexpected UFW status line format
	ErrUnsupported                           // Operation not supported by UFW
)

var (
	ErrInvalidPort      = errors.New("invalid port")
	ErrInvalidProtocol  = errors.New("invalid protocol")
	ErrInvalidDirection = errors.New("invalid direction")
	ErrInvalidIP        = errors.New("invalid IP")
	ErrInvalidPrefix    = errors.New("invalid prefix")
	ErrRuleNotFound     = errors.New("rule not found")
	ErrUFWNotFound      = errors.New("ufw not installed")
	ErrUnsupportedOp    = errors.New("unsupported operation")
)

// UfwError is returned when a UFW command fails.
// Use errors.As to access structured fields.
type UfwError struct {
	Kind    ErrorKind // Category of error
	Message string    // Human-readable message

	Program string   // UFW program name
	Args    []string // Command arguments
	Stderr  string   // Stderr output from UFW
	Code    int      // Exit code (-1 if signal)

	Err error // Wrapped error, if any
}

func (e *UfwError) Error() string {
	switch e.Kind {
	case ErrCommandFailed:
		args := strings.Join(e.Args, " ")
		if e.Code != 0 {
			return fmt.Sprintf("'%s %s' failed with code %d: %s", e.Program, args, e.Code, e.Stderr)
		}
		return fmt.Sprintf("'%s %s' terminated by signal: %s", e.Program, args, e.Stderr)
	case ErrInvalidIPv4:
		return fmt.Sprintf("invalid IPv4 address: %s", e.Message)
	case ErrInvalidIPv6:
		return fmt.Sprintf("invalid IPv6 address: %s", e.Message)
	case ErrParse:
		return fmt.Sprintf("parse error: %s", e.Message)
	case ErrEmptyOutput:
		return "empty output from ufw"
	case ErrUnexpectedStatusLine:
		return fmt.Sprintf("unexpected status line from ufw: %s", e.Message)
	default:
		return e.Message
	}
}

func (e *UfwError) Unwrap() error { return e.Err }

func newCommandFailed(program string, args []string, stderr string, code int) *UfwError {
	return &UfwError{
		Kind:    ErrCommandFailed,
		Program: program,
		Args:    args,
		Stderr:  stderr,
		Code:    code,
	}
}

func newInvalidIPv4(ip string) *UfwError {
	return &UfwError{Kind: ErrInvalidIPv4, Message: ip}
}

func newInvalidIPv6(ip string) *UfwError {
	return &UfwError{Kind: ErrInvalidIPv6, Message: ip}
}

func newParseError(msg string) *UfwError {
	return &UfwError{Kind: ErrParse, Message: msg}
}

var errEmptyOutput = &UfwError{Kind: ErrEmptyOutput}

func newUnexpectedStatusLine(line string) *UfwError {
	return &UfwError{Kind: ErrUnexpectedStatusLine, Message: line}
}
