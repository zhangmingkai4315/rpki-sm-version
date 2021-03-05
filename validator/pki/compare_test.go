package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"testing"
)

func BenchmarkRSA(b *testing.B){
	msg := []byte("test")
	hashed := sha256.Sum256(msg)
	keys := CreateKeys()
	b.ResetTimer()
	for l := 0; l<5; l++{
		b.Run(fmt.Sprintf("loop-%d", l), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				rsa.SignPKCS1v15(rand.Reader, keys[0], crypto.SHA256, hashed[:])
			}
		})
	}

}

func BenchmarkSM2(b *testing.B){
	msg := []byte("test")
	priv, _ := sm2.GenerateKey()
	b.ResetTimer()
	for l := 0; l<5; l++{
		b.Run(fmt.Sprintf("loop-%d", l), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				priv.Sign(rand.Reader, msg, nil)
			}
		})
	}
}


func BenchmarkSignROA_RSA_SHA256(b *testing.B) {
	manager := NewTestManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signROA(manager)
	}
}
func BenchmarkSignROA_SM2_SM3(b *testing.B) {
	manager := NewTestManagerWithSM()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignROAWithSM(manager)
	}
}

func BenchmarkValidateROA_RSA_SHA256(b *testing.B) {
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


func BenchmarkValidateROA_SM2_SM3(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		manager := NewTestManagerWithSM()
		roa, _ := SignROAWithSM(manager)
		AddROAToManifestWithSM(manager, roa)
		b.StartTimer()
		ValidateROAWithSM(manager)
	}
}