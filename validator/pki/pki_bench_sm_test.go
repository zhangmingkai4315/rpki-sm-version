package pki

import (
	"testing"
)


func BenchmarkSignROACertificationWithSM(b *testing.B) {
	manager := NewTestManagerWithSM()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignROAWithSM(manager)
	}
}

func TestValidateROACertificationWithSM(t *testing.T) {
	manager := NewTestManagerWithSM()
	roa, _ := SignROAWithSM(manager)
	AddROAToManifestWithSM(manager, roa)
	count := ValidateROAWithSM(manager)
	if count != 1 {
		t.Errorf("validate fail != %d", count)
	}
}

func BenchmarkValidateROACertificationWithSM(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		manager := NewTestManagerWithSM()
		roa, _ := SignROAWithSM(manager)
		AddROAToManifestWithSM(manager, roa)
		b.StartTimer()
		ValidateROAWithSM(manager)
	}
}
