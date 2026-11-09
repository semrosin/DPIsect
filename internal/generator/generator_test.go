package generator

import "testing"

func TestParseMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    Mode
		wantErr bool
	}{
		{name: "valid session", in: "valid-session", want: ValidSession},
		{name: "raw experiment", in: "raw-experiment", want: RawExperiment},
		{name: "empty", in: "", wantErr: true},
		{name: "unknown", in: "raw", wantErr: true},
		{name: "wrong case", in: "Valid-Session", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseMode(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseMode(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMode(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseMode(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestModeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   Mode
		want string
	}{
		{ValidSession, "valid-session"},
		{RawExperiment, "raw-experiment"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("Mode(%d).String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}
