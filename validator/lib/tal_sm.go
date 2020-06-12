package librpki

import (
	"crypto/x509"
	"encoding/asn1"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)


func (tal *RPKI_TAL) CheckCertificateWithSM(cert *sm2.Certificate) bool {
	if tal.Algorithm == x509.ECDSA {
		a := tal.PublicKey.(*sm2.PublicKey)
		b := cert.PublicKey.(*sm2.PublicKey)
		if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) ==0{
			return  true
		}
	}
	return false
}


func BundleSM2PublicKey(key *sm2.PublicKey) (asn1.BitString, error) {
	keyBytes, err := sm2.MarshalSm2PublicKey(key)
	if err != nil {
		return asn1.BitString{}, err
	}
	return asn1.BitString{Bytes: keyBytes}, nil
}


// Using SM3算法制作hash值
func HashSMPublicKey(key sm2.PublicKey)([]byte, error){
	keyBytesHash, err := asn1.Marshal(key)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("TESTA A %x\n", keyBytesHash)
	hash := sm3.New()
	hash.Write(keyBytesHash)
	hashResult := hash.Sum(nil)
	return hashResult[:], nil
}


