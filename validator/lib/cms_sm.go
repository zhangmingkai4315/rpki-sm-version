package librpki

import (
	"bytes"
	"crypto/ecdsa"

	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"time"
	//"encoding/hex"
)

// SMOID标准定义
// http://gmssl.org/docs/oid.html
var (
	// 1.2.156.10197.1.401 SM3
	// 1.2.156.10197.1.401.2 HMAC-SM3
	SM3OID      = asn1.ObjectIdentifier{1,2,156,10197,1,401}

	//1.2.156.10197.1.301.3 sm2encrypt
	//1.2.156.10197.1.301.3.1 sm2encrypt-recommendedParameters
	//1.2.156.10197.1.301.3.2 sm2encrypt-specifiedParameters
	SM2OID      = asn1.ObjectIdentifier{1,2,156,10197,1,301,3}
)


func DecryptSignatureECDSA(signature []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	//dataDecrypted := ECDSA_public_decrypt(pubKey, signature)
	var signDec SignatureDecoded
	//_, err := asn1.Unmarshal(dataDecrypted, &signDec)
	//if err != nil {
	//	return nil, err
	//}
	return signDec.Hash, nil
}


// EncodeCMSWithSM　支持国密码算法的版本
func EncodeCMSWithSM(certificate []byte, encapContent interface{}, signingTime time.Time) (*CMS, error) {
	val := asn1.RawValue{}
	var signOid asn1.ObjectIdentifier
	switch ec := encapContent.(type) {
	case *ROA:
		roaBytes, err := asn1.Marshal(*ec)
		if err != nil {
			return nil, err
		}
		val.FullBytes = roaBytes
		signOid = RoaOID
	case *Manifest:
		mftBytes, err := asn1.Marshal(*ec)
		if err != nil {
			return nil, err
		}
		val.FullBytes = mftBytes
		signOid = ManifestOID
	default:
		return nil, errors.New("Unknown type of content (not ROA or Manifest)")
	}

	certificateBytes, err := asn1.MarshalWithParams(certificate, "tag:0,implicit")
	if err != nil {
		return nil, err
	}

	type DigestAlg struct {
		OID  asn1.ObjectIdentifier
		Null asn1.RawValue
	}

	type DigestAlgNoNull struct {
		OID asn1.ObjectIdentifier
	}

	dgstBytes, err := asn1.Marshal(DigestAlgNoNull{
		OID: SM3OID,
	})
	if err != nil {
		return nil, err
	}


	oidBytes, err := asn1.Marshal(SM3OID)
	if err != nil {
		return nil, err
	}

	ctOidBytes, err := asn1.Marshal(signOid)
	if err != nil {
		return nil, err
	}
	signingTimeBytes, err := asn1.Marshal(signingTime)
	if err != nil {
		return nil, err
	}
	sm2Alg := DigestAlg{
		OID:  SM2OID,
		Null: asn1.NullRawValue,
	}
	sm2OidBytes, err := asn1.Marshal(sm2Alg)
	if err != nil {
		return nil, err
	}

	attrs := []Attribute{
		Attribute{
			AttrType: ContentTypeOID,
			AttrValue: []asn1.RawValue{
				asn1.RawValue{FullBytes: ctOidBytes},
			},
		},
		Attribute{
			AttrType: SigningTime,
			AttrValue: []asn1.RawValue{
				asn1.RawValue{FullBytes: signingTimeBytes},
			},
		},
	}

	si := []SignerInfo{
		SignerInfo{
			Version: 3,
			DigestAlgorithms: []asn1.RawValue{
				asn1.RawValue{FullBytes: oidBytes},
			},
			SignedAttrs:        attrs,
			SignatureAlgorithm: asn1.RawValue{FullBytes: sm2OidBytes},
		},
	}

	return &CMS{
		OID: SignedDataOID,
		SignedData: CmsSignedData{
			Version: 3,
			DigestAlgorithms: []asn1.RawValue{
				asn1.RawValue{FullBytes: dgstBytes},
			},
			Certificates:     asn1.RawValue{FullBytes: certificateBytes},
			EncapContentInfo: val,
			SignerInfos:      si,
		},
	}, nil
}

// DecodeCMSWithSM　decode the cms byte data to cms structure
func DecodeCMSWithSM(data []byte) (*CMS, error) {
	var c CMS
	_, err := asn1.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (cms *CMS) GetRPKICertificateWithSM() (*RPKI_Certificate, error) {
	rpki_cert, err := DecodeCertificateWithSM(cms.SignedData.Certificates.Bytes)
	if err != nil {
		return nil, err
	}
	return rpki_cert, nil
}


func (cms *CMS) ValidateWithSM(encap []byte, cert *sm2.Certificate) error {
	signedAttributes := cms.SignedData.SignerInfos[0].SignedAttrs

	var messageDigest []byte
	for _, sAttr := range signedAttributes {
		// https://tools.ietf.org/html/rfc5652#section-5.4
		if sAttr.AttrType.Equal(MessageDigest) && len(sAttr.AttrValue) == 1 {
			messageDigest = sAttr.AttrValue[0].Bytes
		}
	}

	h := sm3.New()
	h.Write(encap)
	contentHash := h.Sum(nil)
	if !bytes.Equal(contentHash, messageDigest) {
		return errors.New(fmt.Sprintf("CMS digest (%x) and encapsulated digest (%x) are different", contentHash, messageDigest))
	}

	var sad SignedAttributesDigest
	sad.SignedAttrs = signedAttributes
	b, err := asn1.Marshal(sad)
	if err != nil {
		return err
	}
	h = sm3.New()
	if len(b) < 2 {
		return errors.New("Error with length of signed attributes")
	}
	h.Write(b[2:]) // removes the "sequence"
	signedAttributesHash := h.Sum(nil)

	// Check for public key format (ECDSA?)
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("Public key is not ECDSA")
	}

	decryptedHash, err := DecryptSignatureECDSA(cms.SignedData.SignerInfos[0].Signature, pubKey)
	if err != nil {
		return errors.New(fmt.Sprintf("CMS signature decoding error: %v", err))
	}
	if !bytes.Equal(signedAttributesHash, decryptedHash) {
		return errors.New(fmt.Sprintf("CMS encrypted digest (%x) and calculated digest (%x) are different", decryptedHash, signedAttributesHash))
	}

	return nil
}

