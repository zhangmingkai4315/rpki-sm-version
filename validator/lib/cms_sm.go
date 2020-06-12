package librpki

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"io"
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


//func DecryptSignatureSM(signature []byte, pubKey *sm2.PublicKey) ([]byte, error) {
//	//dataDecrypted := ECDSA_public_decrypt(pubKey, signature)
//
//	//pubKey．
//	dataDecrypted, err := sm2.Encrypt(pubKey, signature)
//	if err != nil{
//		return  nil, err
//	}
//	var signDec SignatureDecoded
//	_, err = asn1.Unmarshal(dataDecrypted, &signDec)
//	if err != nil {
//		return nil, err
//	}
//	return signDec.Hash, nil
//}


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


	signDec := SignatureDecoded{
		Inner: SignatureInner{
			OID:  SM3OID,
			Null: asn1.NullRawValue,
		},
		Hash: signedAttributesHash,
	}
	signEnc, err := asn1.Marshal(signDec)

	// Check for public key format (ECDSA?)
	pubKey, ok := cert.PublicKey.(*sm2.PublicKey)
	if !ok {
		return errors.New("Public key is not ECDSA")
	}
	if pubKey.Verify(signEnc, cms.SignedData.SignerInfos[0].Signature) != true{
		return errors.New(fmt.Sprintf("CMS encrypted digest  are different"))
	}


	return nil
}



func (cms *CMS) SignSM(rand io.Reader, ski []byte, encap []byte, priv interface{}, cert []byte) error {
	privKey, ok := priv.(*sm2.PrivateKey)
	if !ok {
		return errors.New("Private key is not sm2")
	}

	h := sm3.New()
	h.Write(encap)
	messageDigest := h.Sum(nil)
	messageDigestEnc, err := asn1.Marshal(messageDigest)

	digestAttribute := Attribute{
		AttrType:  MessageDigest,
		AttrValue: []asn1.RawValue{asn1.RawValue{FullBytes: messageDigestEnc}},
	}
	cms.SignedData.SignerInfos[0].SignedAttrs = append(cms.SignedData.SignerInfos[0].SignedAttrs, digestAttribute)

	var sad SignedAttributesDigest
	sad.SignedAttrs = cms.SignedData.SignerInfos[0].SignedAttrs
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


	signature, err := EncryptSignatureSM2(rand, signedAttributesHash, privKey)
	if err != nil {
		return err
	}
	cms.SignedData.SignerInfos[0].Signature = signature

	skiM, err := asn1.MarshalWithParams(ski, "tag:0,optional")
	if err != nil {
		return err
	}
	cms.SignedData.SignerInfos[0].Sid = asn1.RawValue{FullBytes: skiM}

	// Causes the byte slice to be encapsulated in a RawValue instead of an OctetString
	var inner asn1.RawValue
	_, err = asn1.Unmarshal(cert, &inner)
	if err != nil {
		return err
	}
	certM, err := asn1.MarshalWithParams([]asn1.RawValue{inner}, "tag:0,optional")
	if err != nil {
		return err
	}
	cms.SignedData.Certificates = asn1.RawValue{FullBytes: certM}
	return nil
}



func EncryptSignatureSM2(rand io.Reader, signature []byte, privKey *sm2.PrivateKey) ([]byte, error) {
	signDec := SignatureDecoded{
		Inner: SignatureInner{
			OID:  SM3OID,
			Null: asn1.NullRawValue,
		},
		Hash: signature,
	}
	signEnc, err := asn1.Marshal(signDec)
	if err != nil {
		return nil, err
	}
	fmt.Printf("TEST 1 %v\n", hex.EncodeToString(signEnc))

	signatureM, err := privKey.Sign(rand, signEnc,nil)

	if err != nil {
		return nil, err
	}

	fmt.Printf("TEST 2 %v\n", hex.EncodeToString(signatureM))

	//ok := privKey.Public().(*sm2.PublicKey).Verify(signEnc, signatureM)
	//if ok == true{
	//	fmt.Printf("verify success")
	//}
	//dec, err := DecryptSignatureRSA(signatureM, privKey.Public().(*rsa.PublicKey))
	//fmt.Printf("TEST 2 %v %v\n", hex.EncodeToString(dec), err)

	return signatureM, nil
}


//func DecryptSignatureSM2(signature []byte, pubKey *sm2.PublicKey, msg []byte) (error) {
//
//	if pubKey.Verify(msg, signature) ==
//	dataDecrypted := SM2_public_decrypt(pubKey, signature)
//	var signDec SignatureDecoded
//	_, err := asn1.Unmarshal(dataDecrypted, &signDec)
//	if err != nil {
//		return nil, err
//	}
//	return signDec.Hash, nil
//}

