package goufw

import (
	"testing"
)

func TestClassifyDeleted(t *testing.T) {
	outcome, err := classifyDeleteOutput("Rule deleted\n", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != deleteOutcomeDeleted {
		t.Fatal("expected Deleted")
	}
}

func TestClassifyDeletedV6(t *testing.T) {
	outcome, err := classifyDeleteOutput("Rule deleted\nRule deleted (v6)\n", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != deleteOutcomeDeleted {
		t.Fatal("expected Deleted")
	}
}

func TestClassifyNotFound(t *testing.T) {
	outcome, err := classifyDeleteOutput("", "Could not delete non-existent rule\n", false)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != deleteOutcomeNotFound {
		t.Fatal("expected NotFound")
	}
}

func TestClassifyNotFoundV6(t *testing.T) {
	outcome, err := classifyDeleteOutput(
		"Could not delete non-existent rule\nCould not delete non-existent rule (v6)\n",
		"", false,
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != deleteOutcomeNotFound {
		t.Fatal("expected NotFound")
	}
}

func TestClassifyMixedDeletedWins(t *testing.T) {
	outcome, err := classifyDeleteOutput("Rule deleted\nCould not delete non-existent rule\n", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != deleteOutcomeDeleted {
		t.Fatal("expected Deleted (deleted wins)")
	}
}

func TestClassifyUnexpectedFailure(t *testing.T) {
	_, err := classifyDeleteOutput("", "some random error\n", false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClassifySuccessNoKnownMessage(t *testing.T) {
	_, err := classifyDeleteOutput("OK\n", "", true)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCombineAllDeleted(t *testing.T) {
	ok, err := combineDeleteOutcomes([]deleteResult{
		{Outcome: deleteOutcomeDeleted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestCombineAllNotFound(t *testing.T) {
	ok, err := combineDeleteOutcomes([]deleteResult{
		{Outcome: deleteOutcomeNotFound},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

func TestCombineNotFoundThenDeleted(t *testing.T) {
	ok, err := combineDeleteOutcomes([]deleteResult{
		{Outcome: deleteOutcomeNotFound},
		{Outcome: deleteOutcomeDeleted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestCombineDeletedThenError(t *testing.T) {
	_, err := combineDeleteOutcomes([]deleteResult{
		{Outcome: deleteOutcomeDeleted},
		{Err: &UfwError{Kind: ErrIO, Message: "boom"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCombineNotFoundOnlyError(t *testing.T) {
	_, err := combineDeleteOutcomes([]deleteResult{
		{Outcome: deleteOutcomeNotFound},
		{Err: &UfwError{Kind: ErrIO, Message: "boom"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDeleteResultStruct(t *testing.T) {
	r := deleteResult{Outcome: deleteOutcomeDeleted}
	if r.Outcome != deleteOutcomeDeleted {
		t.Fatal("expected Deleted")
	}
}
