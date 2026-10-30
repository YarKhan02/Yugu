package fuzz

import "fmt"

// BreakKind names a behavioral inconsistency the fuzzer concluded from a probe.
// These are fuzz-local for now; they are mapped to model finding kinds (and the
// taxonomy widened) in the findings-emission layer.
type BreakKind string

const (
	// BreakNone: the probe behaved acceptably — no finding.
	BreakNone BreakKind = ""
	// BreakCrash: a payload drove the endpoint itself to a 5xx, reproduced on a
	// second fire so it is not a one-off flake.
	BreakCrash BreakKind = "endpoint_crash"
	// BreakWriteReadInconsistency: a body the schema says is invalid was
	// accepted by the write, and the paired read-back then failed — the app
	// stored something it cannot serve.
	BreakWriteReadInconsistency BreakKind = "write_read_inconsistency"
	// BreakNotPersisted: a valid write returned success, but reading the created
	// resource back shows the data was dropped or stored wrong.
	BreakNotPersisted BreakKind = "write_not_persisted"
	// BreakValidationAsymmetry: the same field is validated on one of a resource's
	// write endpoints but not the other (required on create, accepted-when-omitted
	// on update, or the reverse) — inconsistent rules a caller can exploit.
	BreakValidationAsymmetry BreakKind = "validation_asymmetry"
)

// Observation is everything one probe saw: the payload sent (and whether we
// expected it valid), the write's status, and — when a paired read-back ran —
// its status and whether the returned body reflected what was written.
type Observation struct {
	Expected        Payload
	WriteStatus     int
	WriteReproduced bool // a >=500 write confirmed on a second identical fire
	ReadStatus      int  // paired read-back status; 0 means no read-back ran
	ReadBackMatches bool // body reflected the written values; only read when ReadStatus is 2xx
}

// Classify applies the behavioral oracles to one observation and returns the
// break it proves, with a human reason. It is conservative by construction: a
// write the app rejects (4xx) is never a break, and an unreproduced 5xx is left
// as no-finding rather than a flaky crash claim.
func Classify(o Observation) (BreakKind, string) {
	switch {
	case o.WriteStatus >= 500:
		if o.WriteReproduced {
			return BreakCrash, fmt.Sprintf("payload %q drove the endpoint to %d, reproduced", o.Expected.Label, o.WriteStatus)
		}
		return BreakNone, fmt.Sprintf("payload %q returned %d once but did not reproduce", o.Expected.Label, o.WriteStatus)

	case is2xx(o.WriteStatus):
		switch {
		case !o.Expected.Valid && o.ReadStatus >= 500:
			return BreakWriteReadInconsistency, fmt.Sprintf("invalid payload %q was accepted (%d) but the read-back failed (%d)", o.Expected.Label, o.WriteStatus, o.ReadStatus)
		case o.Expected.Valid && is2xx(o.ReadStatus) && !o.ReadBackMatches:
			return BreakNotPersisted, fmt.Sprintf("valid payload %q was accepted (%d) but the read-back did not reflect it", o.Expected.Label, o.WriteStatus)
		default:
			return BreakNone, ""
		}

	default:
		// A 4xx (or other non-success, non-crash) write: the app declined it.
		// Expected for an invalid payload, and not a break for a valid one on its
		// own — that is a separate signal we do not conclude here.
		return BreakNone, ""
	}
}

func is2xx(status int) bool { return status >= 200 && status < 300 }
