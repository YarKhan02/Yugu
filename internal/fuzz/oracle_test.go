package fuzz

import "testing"

func TestClassify(t *testing.T) {
	invalid := Payload{Label: "missing:email", Valid: false}
	valid := Payload{Label: "baseline", Valid: true}

	cases := []struct {
		name string
		obs  Observation
		want BreakKind
	}{
		{
			name: "reproduced 5xx is a crash",
			obs:  Observation{Expected: invalid, WriteStatus: 500, WriteReproduced: true},
			want: BreakCrash,
		},
		{
			name: "unreproduced 5xx is not a crash",
			obs:  Observation{Expected: invalid, WriteStatus: 500, WriteReproduced: false},
			want: BreakNone,
		},
		{
			name: "invalid accepted then read fails",
			obs:  Observation{Expected: invalid, WriteStatus: 201, ReadStatus: 500},
			want: BreakWriteReadInconsistency,
		},
		{
			name: "valid accepted but not persisted",
			obs:  Observation{Expected: valid, WriteStatus: 201, ReadStatus: 200, ReadBackMatches: false},
			want: BreakNotPersisted,
		},
		{
			name: "valid accepted and persisted is clean",
			obs:  Observation{Expected: valid, WriteStatus: 201, ReadStatus: 200, ReadBackMatches: true},
			want: BreakNone,
		},
		{
			// Negative control: the app correctly rejecting an invalid payload is
			// the desired behavior, never a finding.
			name: "invalid rejected is clean",
			obs:  Observation{Expected: invalid, WriteStatus: 400},
			want: BreakNone,
		},
		{
			// Negative control: an invalid payload accepted but whose read-back
			// succeeds is lax, but not one of our oracles — we must not invent it.
			name: "invalid accepted but read ok is not concluded",
			obs:  Observation{Expected: invalid, WriteStatus: 201, ReadStatus: 200, ReadBackMatches: true},
			want: BreakNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := Classify(tc.obs)
			if got != tc.want {
				t.Errorf("Classify = %q (%s), want %q", got, reason, tc.want)
			}
			if got != BreakNone && reason == "" {
				t.Errorf("a break must carry a reason")
			}
		})
	}
}
