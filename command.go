package goufw

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var runner commandRunner

type deleteOutcome int

const (
	deleteOutcomeDeleted  deleteOutcome = iota
	deleteOutcomeNotFound
)

type commandRunner struct{}

func (commandRunner) run(program string, args ...string) error {
	cmd := exec.Command(program, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return newCommandFailed(program, args, string(out), exitErr.ExitCode())
		}
		return &UfwError{Kind: ErrIO, Message: err.Error(), Err: err}
	}
	return nil
}

func (r commandRunner) output(program string, args ...string) (string, error) {
	cmd := exec.Command(program, args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", newCommandFailed(program, args, string(exitErr.Stderr), exitErr.ExitCode())
		}
		return "", &UfwError{Kind: ErrIO, Message: err.Error(), Err: err}
	}
	return string(out), nil
}

func (commandRunner) delete(program string, args ...string) (deleteOutcome, error) {
	cmd := exec.Command(program, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	outcome, cerr := classifyDeleteOutput(stdout.String(), stderr.String(), err == nil)
	if cerr != nil {
		return 0, newCommandFailed(program, args, stderr.String(), exitCode(err))
	}
	return outcome, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func classifyDeleteOutput(stdout, stderr string, success bool) (deleteOutcome, error) {
	deleted := strings.Contains(stdout, "Rule deleted") || strings.Contains(stderr, "Rule deleted")
	notFound := strings.Contains(stdout, "Could not delete non-existent rule") ||
		strings.Contains(stderr, "Could not delete non-existent rule")

	if deleted {
		return deleteOutcomeDeleted, nil
	}
	if notFound {
		return deleteOutcomeNotFound, nil
	}
	if success {
		return 0, newParseError("delete command succeeded but output did not contain expected message")
	}
	return 0, newParseError(fmt.Sprintf("delete command failed with unexpected output: %s", stderr))
}

type deleteResult struct {
	Outcome deleteOutcome
	Err     error
}

func deleteResultOf(program string, args ...string) deleteResult {
	outcome, err := runner.delete(program, args...)
	return deleteResult{Outcome: outcome, Err: err}
}

func combineDeleteOutcomes(results []deleteResult) (bool, error) {
	var anyDeleted bool
	var firstErr error

	for _, r := range results {
		if r.Err != nil {
			if firstErr == nil {
				firstErr = r.Err
			}
		} else if r.Outcome == deleteOutcomeDeleted {
			anyDeleted = true
		}
	}

	if firstErr != nil {
		return false, firstErr
	}
	return anyDeleted, nil
}
