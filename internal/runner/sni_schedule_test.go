package runner

import (
	"reflect"
	"testing"
)

func TestPairedSNIScheduleBalancesOrder(t *testing.T) {
	t.Parallel()

	got, err := pairedSNISchedule("control.example", "web.telegram.org", 3)
	if err != nil {
		t.Fatalf("paired schedule: %v", err)
	}
	want := []string{
		"control.example", "web.telegram.org",
		"web.telegram.org", "control.example",
		"control.example", "web.telegram.org",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("schedule = %v, want %v", got, want)
	}
}

func TestPairedSNIScheduleRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		control   string
		treatment string
		pairs     int
	}{
		{name: "empty control", treatment: "web.telegram.org", pairs: 1},
		{name: "empty treatment", control: "control.example", pairs: 1},
		{name: "same name", control: "example.com", treatment: "example.com", pairs: 1},
		{name: "case-insensitive match", control: "Example.com", treatment: "example.com", pairs: 1},
		{name: "zero pairs", control: "control.example", treatment: "web.telegram.org", pairs: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := pairedSNISchedule(tt.control, tt.treatment, tt.pairs); err == nil {
				t.Fatal("want error for invalid input")
			}
		})
	}
}
