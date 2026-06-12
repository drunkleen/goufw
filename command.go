package goufw

import (
	"fmt"
	"strings"
)

type deleteOutcome int

const (
	deleteOutcomeDeleted deleteOutcome = iota
	deleteOutcomeNotFound
)

type deleteResult struct {
	Outcome deleteOutcome
	Err     error
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
