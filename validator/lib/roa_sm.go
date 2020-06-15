package librpki

import "encoding/asn1"

func DecodeROAWithSM(data []byte) (*RPKI_ROA, error) {
	c, err := DecodeCMSWithSM(data)
	if err != nil {
		return nil, err
	}

	var rawroa ROA
	_, err = asn1.Unmarshal(c.SignedData.EncapContentInfo.FullBytes, &rawroa)

	var inner asn1.RawValue
	_, err = asn1.Unmarshal(rawroa.EContent.Bytes, &inner)
	if err != nil {
		return nil, err
	}
	fullbytes, badformat, err := BadFormatGroup(inner.Bytes)
	if err != nil {
		return nil, err
	}

	var roacontent ROAContent
	_, err = asn1.Unmarshal(fullbytes, &roacontent)
	if err != nil {
		return nil, err
	}

	entries, asn, err := ConvertROAEntries(roacontent)
	if err != nil {
		return nil, err
	}
	// Check for the correct Max Length

	rpki_roa := RPKI_ROA{
		BadFormat: badformat,
		Entries:   entries,
		ASN:       asn,
	}

	rpki_roa.SigningTime, _ = c.GetSigningTime()

	cert, err := c.GetRPKICertificateWithSM()
	if err != nil {
		return &rpki_roa, err
	}
	rpki_roa.Certificate = cert

	// Validate the content of the CMS
	if cert.Certificate != nil {
		err = c.Validate(fullbytes, cert.Certificate)
	} else {
		err = c.ValidateSM(fullbytes, cert.SMCertificate)
	}
	if err != nil {
		rpki_roa.InnerValidityError = err
	} else {
		rpki_roa.InnerValid = true
	}

	// Validates the actual IP addresses
	validEntries, invalidEntries, checkParentEntries := rpki_roa.ValidateIPRoaCertificate(cert)
	rpki_roa.Valids = validEntries
	rpki_roa.Invalids = invalidEntries
	rpki_roa.CheckParent = checkParentEntries

	return &rpki_roa, nil
}
