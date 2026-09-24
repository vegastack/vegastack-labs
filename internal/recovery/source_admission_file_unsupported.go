//go:build !linux && !darwin

package recovery

func LoadSystemSourceAdmission(SourceAdmissionExpectation) (SourceAdmission, error) {
	return SourceAdmission{}, ErrWitnessUnavailable
}
