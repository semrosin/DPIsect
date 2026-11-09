// Package analyzer classifies completed runs from saved observations.
// It reads artifacts only and never sends packets
// (docs/ARCHITECTURE.md §1, §4).
package analyzer

import "context"

// Outcome is a valid experiment result; all three are equal and are
// defined by docs/EXPERIMENTS.md §7.
type Outcome string

const (
	// OutcomeConfirmed: the classification rule held and the
	// observation supports the hypothesis.
	OutcomeConfirmed Outcome = "confirmed"
	// OutcomeRefuted: the classification rule held and the
	// observation contradicts the hypothesis.
	OutcomeRefuted Outcome = "refuted"
	// OutcomeInconclusive: data insufficient or hypotheses not
	// distinguishable; never reported as confirmation.
	OutcomeInconclusive Outcome = "inconclusive"
)

// Observations points at the artifacts of one run. All paths live
// outside git (docs/EXPERIMENTS.md §4, docs/SAFETY.md §5).
type Observations struct {
	ClientPCAP string
	ServerPCAP string
	HelperLog  string
	RunnerLog  string
}

// Results mirrors the results block of the report template
// (docs/EXPERIMENTS.md §4).
type Results struct {
	Observation          string
	CompatibleHypotheses []string
	ExcludedHypotheses   []string
	InconclusiveReason   string
}

// Classification is the analyzer→report result.
type Classification struct {
	Outcome Outcome
	Results Results
}

// Classifier applies a classification rule that was fixed before the
// first packet was sent (docs/EXPERIMENTS.md §2).
type Classifier interface {
	Classify(ctx context.Context, obs Observations) (Classification, error)
}
