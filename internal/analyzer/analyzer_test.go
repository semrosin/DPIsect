package analyzer

import "testing"

func TestOutcomeValues(t *testing.T) {
	t.Parallel()

	// The wire values are the report statuses of docs/EXPERIMENTS.md
	// §7 and must not drift.
	tests := []struct {
		in   Outcome
		want string
	}{
		{OutcomeConfirmed, "confirmed"},
		{OutcomeRefuted, "refuted"},
		{OutcomeInconclusive, "inconclusive"},
	}
	for _, tt := range tests {
		if got := string(tt.in); got != tt.want {
			t.Errorf("outcome = %q, want %q", got, tt.want)
		}
	}
}
