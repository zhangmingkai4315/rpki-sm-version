package librpki

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"time"
)

func DecodeCertificateWithSM(data []byte) (*RPKI_Certificate, error) {
	cert, err := sm2.ParseCertificate(data)
	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	publicKey := cert.PublicKey.(*ecdsa.PublicKey)

	pub := new(sm2.PublicKey)
	pub.X = publicKey.X
	pub.Y = publicKey.Y
	pub.Curve = publicKey.Curve
	cert.PublicKey = pub

	rpki_cert := RPKI_Certificate{
		SMCertificate: cert,
	}
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(IpAddrBlock) {
			addresses, err := DecodeIPAddressBlock(extension.Value)
			rpki_cert.IPAddresses = addresses
			if err != nil {
				return &rpki_cert, err
			}
		} else if extension.Id.Equal(AutonomousSysIds) {
			asnsnum, asnsrdi, err := DecodeASN(extension.Value)
			rpki_cert.ASNums = asnsnum
			rpki_cert.ASNRDI = asnsrdi
			if err != nil {
				return &rpki_cert, err
			}
		} else if extension.Id.Equal(SubjectInfoAccess) {
			sias, err := DecodeSubjectInformationAccess(extension.Value)
			rpki_cert.SubjectInformationAccess = sias
			if err != nil {
				return &rpki_cert, err
			}
		}
	}

	return &rpki_cert, nil
}

func (cert *RPKI_Certificate) ValidateWithSM(parent *RPKI_Certificate) error {
	if cert.SMCertificate == nil {
		return errors.New("No certificate found")
	}
	if parent.SMCertificate == nil {
		return errors.New("No certificate found in parent")
	}
	err := cert.SMCertificate.CheckSignatureFrom(parent.SMCertificate)
	if err != nil && err == sm2.ErrUnsupportedAlgorithm {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

func (cert *RPKI_Certificate) ValidateTimeWithSM(comp time.Time) error {
	if cert.SMCertificate == nil {
		return errors.New("No certificate found")
	}
	if cert.SMCertificate.NotBefore.After(comp) {
		return errors.New(fmt.Sprintf("Certificate beginning of validity: %v is after: %v", cert.SMCertificate.NotBefore, comp))
	}
	if comp.After(cert.SMCertificate.NotAfter) {
		return errors.New(fmt.Sprintf("Certificate end of validity: %v is before: %v", cert.SMCertificate.NotBefore, comp))
	}
	return nil
}
