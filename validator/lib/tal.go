package librpki

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"io"
	"strings"
)

var (
	RSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type RPKI_TAL struct {
	URI       string
	Algorithm x509.PublicKeyAlgorithm
	OID       asn1.ObjectIdentifier
	PublicKey interface{}
}

func (tal *RPKI_TAL) CheckCertificate(cert *x509.Certificate) bool {
	if tal.Algorithm == cert.PublicKeyAlgorithm {
		switch tal.Algorithm {
		case x509.RSA:
			a := tal.PublicKey.(*rsa.PublicKey)
			b := cert.PublicKey.(*rsa.PublicKey)
			if a.N.Cmp(b.N) == 0 && a.E == b.E {
				return true
			}

		}
	}
	return false
}

func DeleteLineEnd(line string) string {
	if len(line) > 1 && line[len(line)-2] == 0xd {
		line = line[0 : len(line)-2]
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[0 : len(line)-1]
	}
	return line
}

func CreateTAL(uri string, pubkey interface{}) (*RPKI_TAL, error) {
	var pubkeyc interface{}
	var isSMAlgorithem bool

	switch pubkeyt := pubkey.(type) {
	case *rsa.PublicKey:
		pubkeyc = *pubkeyt
		isSMAlgorithem = false
	case rsa.PublicKey:
		pubkeyc = pubkeyt
		isSMAlgorithem = false
	case *sm2.PublicKey:
		pubkeyc = *pubkeyt
		isSMAlgorithem = true
	case sm2.PublicKey:
		pubkeyc = pubkeyt
		isSMAlgorithem = true
	default:
		return nil, errors.New("Public key is not RSA or SM2")
	}
	if isSMAlgorithem == true {
		return &RPKI_TAL{
			URI:       uri,
			Algorithm: x509.ECDSA,
			OID:       SM2OID,
			PublicKey: pubkeyc,
		}, nil
	}
	return &RPKI_TAL{
		URI:       uri,
		Algorithm: x509.RSA,
		OID:       RSA,
		PublicKey: pubkeyc,
	}, nil
}

func EncodeTAL(tal *RPKI_TAL) ([]byte, error) {
	return EncodeTALSize(tal, 64)
}

func HashPublicKey(key interface{}) ([]byte, error) {
	switch keyc := key.(type) {
	case *rsa.PublicKey:
		return HashRSAPublicKey(*keyc)
	case rsa.PublicKey:
		return HashRSAPublicKey(keyc)

	case *sm2.PublicKey:
		return HashSMPublicKey(*keyc)
	case sm2.PublicKey:
		return HashSMPublicKey(keyc)
	default:
		return nil, errors.New("Public key is not RSA or SM2")
	}
}

func HashRSAPublicKey(key rsa.PublicKey) ([]byte, error) {
	keyBytesHash, err := asn1.Marshal(key)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("TESTA A %x\n", keyBytesHash)

	hash := sha1.Sum(keyBytesHash)
	return hash[:], nil
}

func BundleRSAPublicKey(key rsa.PublicKey) (asn1.BitString, error) {
	keyBytes, err := asn1.Marshal(key)
	if err != nil {
		return asn1.BitString{}, err
	}
	return asn1.BitString{Bytes: keyBytes}, nil
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func EncodeTALSize(tal *RPKI_TAL, split int) ([]byte, error) {
	var bs asn1.BitString
	var err error
	if tal.OID.Equal(RSA) {
		keyRaw := tal.PublicKey.(rsa.PublicKey)
		bs, err = BundleRSAPublicKey(keyRaw)
		if err != nil {
			return nil, err
		}
	} else if tal.OID.Equal(SM2OID) {
		//var r pkixPublicKey
		keyRaw := tal.PublicKey.(sm2.PublicKey)
		//keyRaw := tal.PublicKey.(sm2.PublicKey)
		bs, err = BundleSM2PublicKey(&keyRaw)
		if err != nil {
			return nil, err
		}

		//bsraw, err := sm2.MarshalSm2PublicKey(&keyRaw)
		//_, err = asn1.Unmarshal(bsraw, r)
		//if err != nil{
		//	return nil,err
		//}
		//bs = r.BitString
	} else {
		return nil, errors.New("TAL does not contain a RSA or SM2 key")
	}

	type subjectPublicKeyInfo struct {
		Type struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue
		}
		BS asn1.BitString
	}

	spki := subjectPublicKeyInfo{
		Type: struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue
		}{
			OID:  tal.OID,
			Null: asn1.NullRawValue,
		},
		BS: bs,
	}
	keyBytesData, err := asn1.Marshal(spki)
	if err != nil {
		return nil, err
	}
	key := base64.RawStdEncoding.EncodeToString(keyBytesData)
	if split > 0 {
		keySplit := make([]string, len(key)/split+1)
		for i := 0; i < len(key)/split+1; i++ {
			max := (i + 1) * split
			if len(key) < max {
				max = len(key)
			}
			keySplit[i] = key[i*split : max]
		}
		key = strings.Join(keySplit, "\n")
	}

	return []byte(fmt.Sprintf("%v\n\n%v", tal.URI, key)), nil
}

func DecodeTAL(data []byte) (*RPKI_TAL, error) {
	buf := bytes.NewBufferString(string(data))
	url, err := buf.ReadString('\n')
	url = DeleteLineEnd(url)
	if err != nil {
		return nil, err
	}
	b, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}
	if b == 0xd {
		b, err = buf.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	b64, err := buf.ReadString('\n')
	b64 = DeleteLineEnd(b64)
	for err == nil {
		var b64tmp string
		b64tmp, err = buf.ReadString('\n')
		b64tmp = DeleteLineEnd(b64tmp)
		b64 += b64tmp
	}
	if err != io.EOF {
		return nil, err
	}

	d, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	type subjectPublicKeyInfo struct {
		Type struct {
			OID asn1.ObjectIdentifier
		}
		BS asn1.BitString
	}

	var inner subjectPublicKeyInfo
	_, err = asn1.Unmarshal(d, &inner)
	if err != nil {
		return nil, err
	}

	tal := &RPKI_TAL{
		URI: url,
		OID: inner.Type.OID,
	}

	if tal.OID.Equal(RSA) {
		tal.Algorithm = x509.RSA

		var inner2 rsa.PublicKey
		_, err = asn1.Unmarshal(inner.BS.Bytes, &inner2)

		if err != nil {
			return nil, err
		}
		tal.PublicKey = &inner2
	} else if tal.OID.Equal(SM2OID) {
		tal.Algorithm = x509.ECDSA

		//var inner2 sm2.PublicKey
		//_, err = asn1.Unmarshal(inner.BS.Bytes, &inner2)
		inner2, err := sm2.ParseSm2PublicKey(inner.BS.Bytes)

		//inner, err := sm2.ParsePKIXPublicKey(inner.BS.Bytes)
		if err != nil {
			return nil, err
		}
		tal.PublicKey = inner2
		//if pk, ok := inner.(*sm2.PublicKey); ok == true{
		//	tal.PublicKey = pk
		//}
	} else {
		tal.PublicKey = inner.BS.Bytes
	}
	return tal, nil
}
