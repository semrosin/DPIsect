package dnsprobe

import (
	"context"
	"errors"
	"testing"
)

func TestCheckAgreeingResolvers(t *testing.T) {
	t.Parallel()

	c := &checker{
		system: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.1", "192.0.2.2"}, nil
		},
		independent: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.2", "192.0.2.1"}, nil
		},
		dialTCP: func(context.Context, string) bool { return true },
	}

	rep, err := c.Check(t.Context(), "example.test", "192.0.2.1", 443)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !rep.AddrsMatch {
		t.Error("AddrsMatch = false, want true (order must not matter)")
	}
	if !rep.TCPReachable {
		t.Error("TCPReachable = false, want true")
	}
	if rep.Host != "example.test" {
		t.Errorf("Host = %q, want example.test", rep.Host)
	}
}

func TestCheckDivergingResolvers(t *testing.T) {
	t.Parallel()

	c := &checker{
		system: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.1"}, nil
		},
		independent: func(context.Context, string) ([]string, error) {
			return []string{"198.51.100.1"}, nil
		},
		dialTCP: func(context.Context, string) bool { return false },
	}

	rep, err := c.Check(t.Context(), "example.test", "192.0.2.1", 443)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if rep.AddrsMatch {
		t.Error("AddrsMatch = true, want false")
	}
	if rep.TCPReachable {
		t.Error("TCPReachable = true, want false (G02 is data, not error)")
	}
}

func TestCheckRejectsEmptyHost(t *testing.T) {
	t.Parallel()

	c := &checker{}
	if _, err := c.Check(t.Context(), "", "192.0.2.1", 443); err == nil {
		t.Fatal("want error for empty host, got nil")
	}
}

func TestCheckRequiresIndependentResolver(t *testing.T) {
	t.Parallel()

	c := &checker{
		system: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.1"}, nil
		},
	}
	if _, err := c.Check(t.Context(), "example.test", "192.0.2.1", 443); err == nil {
		t.Fatal("want error for missing independent resolver, got nil")
	}
}

func TestCheckPropagatesLookupFailures(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("servfail")
	c := &checker{
		system: func(context.Context, string) ([]string, error) {
			return nil, wantErr
		},
		independent: func(context.Context, string) ([]string, error) {
			return []string{"192.0.2.1"}, nil
		},
	}
	if _, err := c.Check(t.Context(), "example.test", "192.0.2.1", 443); !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wrapped %v", err, wantErr)
	}
}
