package librpki
import (
	"encoding/asn1"
)


func DecodeManifestWithSM(data []byte) (*RPKI_Manifest, error) {
	c, err := DecodeCMS(data)
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	_, err = asn1.Unmarshal(c.SignedData.EncapContentInfo.FullBytes, &manifest)
	if err != nil {
		return nil, err
	}

	var inner asn1.RawValue
	_, err = asn1.Unmarshal(manifest.EContent.Bytes, &inner)
	if err != nil {
		return nil, err
	}

	fullbytes, badformat, err := BadFormatGroup(inner.Bytes)
	if err != nil {
		return nil, err
	}

	fullbytes, _ = BER2DER(fullbytes)
	var mc ManifestContent
	_, err = asn1.Unmarshal(fullbytes, &mc)
	if err != nil {
		return nil, err
	}

	rpki_manifest := &RPKI_Manifest{
		Content:   mc,
		BadFormat: badformat}

	cert, err := c.GetRPKICertificateWithSM()
	if err != nil {
		return rpki_manifest, err
	}
	rpki_manifest.Certificate = cert

	// Validate the content of the CMS
	err = c.ValidateWithSM(fullbytes, cert.SMCertificate)
	if err != nil {
		rpki_manifest.InnerValidityError = err
	} else {
		rpki_manifest.InnerValid = true
	}

	return rpki_manifest, nil
}

