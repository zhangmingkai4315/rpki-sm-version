package pki

import (
	"testing"
)

func BenchmarkSignROACertification(b *testing.B) {
	manager := NewTestManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signROA(manager)
	}
}

func TestValidateROACertification(t *testing.T) {
	manager := NewTestManager()
	roa, _ := signROA(manager)
	addROAToManifest(manager, roa)
	count := validateROA(manager)
	if count != 1 {
		t.Errorf("validate fail != %d", count)
	}
}


func BenchmarkValidateROACertification(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		manager := NewTestManager()
		roa, _ := signROA(manager)
		addROAToManifest(manager, roa)
		b.StartTimer()
		validateROA(manager)
	}
}
