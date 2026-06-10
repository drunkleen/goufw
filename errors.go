package goufw

import (
	"errors"
	"fmt"
	"strings"
)

type ErrorKind int

const (
	ErrIO                  ErrorKind = iota
	ErrCommandFailed
	ErrInvalidIPv4
	ErrInvalidIPv6
	ErrParse
	ErrEmptyOutput
	ErrUnexpectedStatusLine
)

type UfwError struct {
	Kind    ErrorKind
	Message string

	Program string
	Args    []string
	Stderr  string
	Code    int

	Err error
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

func isNotFound(err error) bool {
	var ue *UfwError
	if errors.As(err, &ue) {
		return ue.Kind == ErrCommandFailed && ue.Code != 0
	}
	return false
}
