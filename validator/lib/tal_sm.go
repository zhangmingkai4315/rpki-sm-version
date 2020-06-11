package librpki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
)


func (tal *RPKI_TAL) CheckCertificateWithSM(cert *sm2.Certificate) bool {
	if tal.Algorithm == x509.ECDSA {
		a := tal.PublicKey.(*ecdsa.PublicKey)
		b := cert.PublicKey.(*ecdsa.PublicKey)
		if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) ==0{
			return  true
		}
	}
	return false
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



func BundleSM2PublicKey(key *sm2.PublicKey) (asn1.BitString, error) {
	keyBytes, err := sm2.MarshalSm2PublicKey(key)
	if err != nil {
		return asn1.BitString{}, err
	}
	return asn1.BitString{Bytes: keyBytes}, nil

}

