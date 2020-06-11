package pki

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cloudflare/cfrpki/validator/lib"
)



func (sm *SimpleManager) ExploreAddWithSM(file *PKIFile, data *SeekFile, addInvalidChilds bool) {
	sm.Explored[file.ComputePath()] = true
	valid, subFiles, res, err := sm.Validator.AddResourceWithSM(file, data.Data)
	if err != nil {
		if sm.Log != nil {
			sm.Log.Errorf("Error adding Resource %v: %v", file.Path, err)
		}
	}
	if !valid && err == nil {
		if sm.Log != nil {
			sm.Log.Warnf("Resource %v is invalid: %v", file.Path, err)
		}
	}
	for _, subFile := range subFiles {
		subFile.Parent = file
	}
	if addInvalidChilds || valid {
		sm.PutFiles(subFiles)
		sm.PathOfResource[res] = file
	}
}

func (sm *SimpleManager) ExploreWithSM(notMFT bool, addInvalidChilds bool) int {
	hasMore := sm.HasMore()
	var count int
	for hasMore {
		// Log errors
		var err error
		var file *PKIFile

		file, hasMore, err = sm.GetNextExplore()
		if err != nil {
			if sm.Log != nil {
				sm.Log.Errorf("Error getting file: %v", err)
			}
		} else {
			count++
		}
		if !notMFT || file.Type != TYPE_MFT {
			data, err := sm.GetNextFile(file)

			if err != nil {
				if sm.Log != nil {
					sm.Log.Errorf("Error exploring file: %v", err)
				}
			} else if data != nil {
				sm.ExploreAddWithSM(file, data, addInvalidChilds)
				hasMore = sm.HasMore()
			} else {
				if sm.Log != nil {
					sm.Log.Debugf("GetNextFile returned nothing")
				}
			}
		} else {
			err = sm.GetNextRepository(file, sm.ExploreAdd)
			sm.Explored[file.Repo] = true
			if err != nil {
				if sm.Log != nil {
					sm.Log.Errorf("Error exploring repository: %v", err)
				}
			}
		}
		hasMore = sm.HasMore()
	}
	return count
}


func (v *Validator) AddCertWithSM(cert *librpki.RPKI_Certificate, trust bool) (bool, []*PKIFile, *Resource, error) {
	pathCert := ExtractPathCertWithSM(cert)

	ski := string(cert.SMCertificate.SubjectKeyId)
	aki := string(cert.SMCertificate.AuthorityKeyId)

	_, exists := v.Objects[ski]
	if exists {
		return false, nil, nil, errors.New(fmt.Sprintf("A certificate with Subject Key Id: %v already exists", hex.EncodeToString(cert.SMCertificate.SubjectKeyId)))
	}

	_, hasParentValid := v.ValidObjects[aki]
	parent, hasParent := v.Objects[aki]
	res := ObjectToResource(cert)
	res.Parent = parent

	var valid bool
	if hasParentValid || trust {
		valid = true
	}

	err := v.ValidateCertificateWithSM(cert, trust)
	if err != nil {
		valid = false
	}

	if hasParent && parent != nil && valid {
		parent.Childs = append(parent.Childs, res)

		v.CertsSerial[aki+cert.SMCertificate.SerialNumber.String()] = res
	}

	if valid {
		v.ValidObjects[ski] = res
	}
	v.Objects[ski] = res

	return valid, pathCert, res, err
}


func ExtractPathCertWithSM(cert *librpki.RPKI_Certificate) []*PKIFile {
	fileList := make([]*PKIFile, 0)

	var repo string
	item := &PKIFile{
		Type: TYPE_MFT,
	}
	var add bool
	for _, sia := range cert.SubjectInformationAccess {
		if sia.AccessMethod.Equal(Manifest) {
			item.Path = string(sia.GeneralName)
			add = true
		} else if sia.AccessMethod.Equal(CARepository) {
			repo = string(sia.GeneralName)
			item.Repo = repo
		}
	}

	for _, crl := range cert.SMCertificate.CRLDistributionPoints {
		item := &PKIFile{
			Type: TYPE_CRL,
			Repo: repo,
			Path: crl,
		}
		fileList = append(fileList, item)
	}

	if add {
		fileList = append(fileList, item)
	}
	return fileList
}


func (v *Validator) ValidateCertificateWithSM(cert *librpki.RPKI_Certificate, trust bool) error {
	ski := cert.SMCertificate.SubjectKeyId

	// Check time validity
	err := cert.ValidateTimeWithSM(v.Time)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate due to expiration date %x: %v", ski, err))
	}

	if trust {
		return nil
	}

	// Check against parent
	aki := cert.SMCertificate.AuthorityKeyId
	parent, hasParent := v.ValidObjects[string(aki)]
	if !hasParent {
		return errors.New(fmt.Sprintf("Could not find parent %x for certificate %x", aki, ski))
	}

	parentCert, ok := parent.Resource.(*librpki.RPKI_Certificate)
	if !ok {
		return errors.New(fmt.Sprintf("Parent %x of %x is not a RPKI Certificate", ski, aki))
	}
	err = cert.ValidateWithSM(parentCert)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not validate certificate %x against parent %x: %v", ski, aki, err))
	}

	// Check presence in revokation lists
	_, revoked := v.Revoked[string(aki)+cert.SMCertificate.SerialNumber.String()]
	if revoked {
		return errors.New(fmt.Sprintf("Certificate was revoked by issuer %x", ski))
	}

	// Check IPs
	valids, invalids, checkParent := cert.ValidateIPCertificate(parentCert)
	chain := parent.Parent
	for chain != nil && len(checkParent) > 0 {
		key := parentCert.SMCertificate.AuthorityKeyId
		upperCert, found := v.ValidObjects[string(key)]
		if !found {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not valid", key, ski))
		}
		chainCert, ok := upperCert.Resource.(*librpki.RPKI_Certificate)
		if !ok {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not a RPKI Certificate", key, ski))
		}
		validsTmp, invalidsTmp, checkParentTmp := librpki.ValidateIPCertificateList(checkParent, chainCert)
		valids = append(valids, validsTmp...)
		invalids = append(invalids, invalidsTmp...)
		checkParent = checkParentTmp
		chain = chain.Parent
	}
	if len(invalids) > 0 {
		return errors.New(fmt.Sprintf("%x contains invalid IP addresses: %v", ski, invalids))
	}

	// Check ASNs
	validsASN, invalidsASN, checkParentASN := cert.ValidateASNCertificate(parentCert)
	chain = parent.Parent
	for chain != nil && len(checkParentASN) > 0 {
		key := parentCert.SMCertificate.AuthorityKeyId
		upperCert, found := v.ValidObjects[string(key)]
		if !found {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not valid", key, ski))
		}
		chainCert, ok := upperCert.Resource.(*librpki.RPKI_Certificate)
		if !ok {
			return errors.New(fmt.Sprintf("One of the parents (%x) of %x is not a RPKI Certificate", key, ski))
		}
		validsTmp, invalidsTmp, checkParentTmp := librpki.ValidateASNCertificateList(checkParentASN, chainCert)
		validsASN = append(validsASN, validsTmp...)
		invalidsASN = append(invalidsASN, invalidsTmp...)
		checkParentASN = checkParentTmp
		chain = chain.Parent
	}
	if len(invalidsASN) > 0 {
		return errors.New(fmt.Sprintf("%x contains invalid ASNs: %v", ski, invalidsASN))
	}

	return nil
}

func (v *Validator) AddResourceWithSM(pkifile *PKIFile, data []byte) (bool, []*PKIFile, *Resource, error) {
	resType := pkifile.Type
	switch resType {
	case TYPE_TAL:
		tal, err := librpki.DecodeTAL(data)
		if err != nil {
			return false, nil, nil, err
		}
		pathCert, res, err := v.AddTAL(tal)
		if res == nil {
			return true, pathCert, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
		}
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}
		return true, pathCert, res, err
	case TYPE_CER:
		cert, err := librpki.DecodeCertificateWithSM(data)
		if err != nil {
			return false, nil, nil, err
		}
		if pkifile != nil && pkifile.Parent != nil && pkifile.Parent.Type == TYPE_TAL {
			talComp, ok := v.TALs[pkifile.Path]
			if ok {
				if cert.SMCertificate == nil{
					talValidation := talComp.Resource.(*librpki.RPKI_TAL).CheckCertificate(cert.Certificate)
					if !talValidation {
						return false, nil, nil, errors.New("Certificate was not validated against TAL")
					}
				}else{
					talValidation := talComp.Resource.(*librpki.RPKI_TAL).CheckCertificateWithSM(cert.SMCertificate)
					if !talValidation {
						return false, nil, nil, errors.New("Certificate was not validated against TAL")
					}
				}
			}
		}
		var valid bool
		var pathCert []*PKIFile
		var res *Resource
		if cert.SMCertificate == nil{
			valid, pathCert, res, err = v.AddCert(cert, pkifile.Trust)
		}else{
			valid, pathCert, res, err = v.AddCertWithSM(cert, pkifile.Trust)
		}

		if res == nil {
			return valid, pathCert, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
		}
		res.Type = TYPE_CER
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}
		return valid, pathCert, res, err
	case TYPE_ROA:
		roa, err := librpki.DecodeROA(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, res, err := v.AddROA(pkifile, roa)
		if res == nil {
			return valid, nil, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
		}
		res.File = pkifile
		return valid, nil, res, err
	case TYPE_MFT:
		mft, err := librpki.DecodeManifestWithSM(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, pathCert, res, err := v.AddManifest(pkifile, mft)
		if res == nil {
			return valid, nil, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
		}
		res.File = pkifile
		for _, pc := range pathCert {
			pc.Parent = pkifile
		}
		return valid, pathCert, res, err
	case TYPE_CRL:
		// https://tools.ietf.org/html/rfc5280
		crl, err := x509.ParseDERCRL(data)
		if err != nil {
			return false, nil, nil, err
		}
		valid, res, err := v.AddCRL(crl)
		if res == nil {
			return valid, nil, res, errors.New(fmt.Sprintf("Resource is empty: %v", err))
		}
		res.File = pkifile
		return valid, nil, res, err
	}
	return false, nil, nil, errors.New("Unknown file type")
}
