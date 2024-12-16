package detectors

type VerificationStatus int

const (
	Skipped VerificationStatus = iota
	Error
	ConfirmedValid
	ConfirmedInvalid
)
