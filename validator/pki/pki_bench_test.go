package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	librpki "github.com/cloudflare/cfrpki/validator/lib"
	"math/big"
	"net"
	"testing"
	"time"
)

const (
	ROOT_KEY_INDEX       = 0
	MANIFEST_KEY_INDEX_1 = 1
	MANIFEST_KEY_INDEX_2 = 2
	ROA_KEY_INDEX        = 3
	SUBCERT_KEY_INDEX    = 4

	IP_BLOCK_EXTENSION_1 = 5
	IP_BLOCK_EXTENSION_2 = 6
	ASN_EXTENSION_1      = 7
	ASN_EXTENSION_2      = 8

	SIA_EXTENSION     = 9
	SIA_EXTENSION_SUB = 10
	POLIC_EXTENSION   = 11
)

type TestManager struct {
	fs           *TestingFileSeeker
	keys         []*rsa.PrivateKey
	publicKeys   []crypto.PublicKey
	skiPublicKey [][]byte

	tal           *librpki.RPKI_TAL
	talPath       string
	pathExtension []*pkix.Extension
	rootCert      *x509.Certificate
	orgCert       *x509.Certificate

	orgHash [32]byte
	crlHash [32]byte

	validatorManager *SimpleManager
}


func NewTestManager() *TestManager {
	genTime := time.Now().UTC()
	validity := time.Duration(time.Hour * 24 * 365 * 10)

	keys := CreateKeys()
	fs := NewFileSeeker()
	publicKeys := make([]crypto.PublicKey, 0)
	for _, k := range keys {
		publicKeys = append(publicKeys, k.Public())
	}
	skiPublicKey := make([][]byte, 0)
	for _, k := range publicKeys {
		h, _ := librpki.HashPublicKey(k)
		skiPublicKey = append(skiPublicKey, h)
	}

	//创建TAL
	talPath := "rsync://lambda/module/example.tal"
	tal, _ := librpki.CreateTAL("rsync://lambda/module/root.cer", publicKeys[ROOT_KEY_INDEX])

	// 涉及修改rsa和sm的兼容
	data, _ := librpki.EncodeTAL(tal)
	fs.AddFile(talPath, data)

	_, net1, _ := net.ParseCIDR("0.0.0.0/0")
	_, net2, _ := net.ParseCIDR("::/0")

	ipBlocks := []librpki.IPCertificateInformation{
		&librpki.IPNet{
			IPNet: net1,
		},
		&librpki.IPNet{
			IPNet: net2,
		},
	}
	ipblocksExtension, _ := librpki.EncodeIPAddressBlock(ipBlocks)
	ipBlocks2 := []librpki.IPCertificateInformation{
		&librpki.IPAddressNull{
			Family: 1,
		},
	}
	ipblocksExtension2, _ := librpki.EncodeIPAddressBlock(ipBlocks2)

	pathExtension := make([]*pkix.Extension, 0)

	parentPath, _ := librpki.EncodeInfoAccess(true, "rsync://lambda/module/root.cer")
	pathExtension = append(pathExtension, parentPath)

	manifestPath, _ := librpki.EncodeInfoAccess(false, "rsync://lambda/module/root.mft")
	pathExtension = append(pathExtension, manifestPath)

	manifestPath2, _ := librpki.EncodeInfoAccess(false, "rsync://lambda/module/certs/test.mft")
	pathExtension = append(pathExtension, manifestPath2)

	roaPath, _ := librpki.EncodeInfoAccess(false, "rsync://lambda/module/certs/test.roa")
	pathExtension = append(pathExtension, roaPath)

	parentSubPath, _ := librpki.EncodeInfoAccess(true, "rsync://lambda/module/test.cer")
	pathExtension = append(pathExtension, parentSubPath)

	pathExtension = append(pathExtension, ipblocksExtension)
	pathExtension = append(pathExtension, ipblocksExtension2)

	policy, _ := librpki.EncodePolicyInformation("http://example.com/cps.html")

	asnsBlock := []librpki.ASNCertificateInformation{
		&librpki.ASNRange{
			Min: 0,
			Max: 4294967295,
		},
	}

	//
	asnExtension, _ := librpki.EncodeASN(asnsBlock, nil)

	asnsBlock2 := []librpki.ASNCertificateInformation{
		&librpki.ASNull{},
	}
	asnExtension2, _ := librpki.EncodeASN(asnsBlock2, nil)

	pathExtension = append(pathExtension, asnExtension)
	pathExtension = append(pathExtension, asnExtension2)

	sias := []*librpki.SIA{
		&librpki.SIA{
			AccessMethod: librpki.CertRepository,
			GeneralName:  []byte("rsync://lambda/module/"),
		},
		&librpki.SIA{
			AccessMethod: librpki.SIAManifest,
			GeneralName:  []byte("rsync://lambda/module/root.mft"),
		},
	}
	siaExtension, _ := librpki.EncodeSIA(sias)
	siasSub := []*librpki.SIA{
		&librpki.SIA{
			AccessMethod: librpki.CertRepository,
			GeneralName:  []byte("rsync://lambda/module/certs/"),
		},
		&librpki.SIA{
			AccessMethod: librpki.SIAManifest,
			GeneralName:  []byte("rsync://lambda/module/certs/test.mft"),
		},
	}
	siaExtensionSub, _ := librpki.EncodeSIA(siasSub)

	pathExtension = append(pathExtension, siaExtension)
	pathExtension = append(pathExtension, siaExtensionSub)

	rootCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Root",
		},
		ExtraExtensions: []pkix.Extension{
			*siaExtension,
			*ipblocksExtension,
			*asnExtension,
			*policy,
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiPublicKey[ROOT_KEY_INDEX],
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
	}

	certBytesRoot, _ := x509.CreateCertificate(
		rand.Reader, rootCert, rootCert, publicKeys[ROOT_KEY_INDEX], keys[ROOT_KEY_INDEX])
	fs.AddFile("rsync://lambda/module/root.cer", certBytesRoot)

	crlBytes, _ := librpki.CreateCRL(rootCert, rand.Reader, keys[ROOT_KEY_INDEX], []pkix.RevokedCertificate{}, genTime, genTime.Add(validity), big.NewInt(1))

	fs.AddFile("rsync://lambda/module/root.crl", crlBytes)

	// Organization
	orgCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(43),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Sub",
		},
		ExtraExtensions: []pkix.Extension{
			*siaExtensionSub,
			*ipblocksExtension,
			*asnExtension,
			*policy,
			*parentPath,
		},
		AuthorityKeyId:        skiPublicKey[ROOT_KEY_INDEX],
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiPublicKey[SUBCERT_KEY_INDEX],
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
		CRLDistributionPoints: []string{"rsync://lambda/module/root.crl"},
	}
	// 签名者私钥，以及被签名者的公钥信息　这里使用root证书来完成SubCert证书的签名
	certBytesOrg, _ := x509.CreateCertificate(
		rand.Reader, orgCert, rootCert, publicKeys[SUBCERT_KEY_INDEX], keys[ROOT_KEY_INDEX])

	fs.AddFile("rsync://lambda/module/test.cer", certBytesOrg)

	orghash := sha256.Sum256(certBytesOrg)
	// CRL
	crlBytes, _ = librpki.CreateCRL(orgCert, rand.Reader, keys[SUBCERT_KEY_INDEX], []pkix.RevokedCertificate{}, genTime, genTime.Add(validity), big.NewInt(1))
	fs.AddFile("rsync://lambda/module/certs/test.crl", crlBytes)
	crlhash := sha256.Sum256(crlBytes)

	pathExtension = append(pathExtension, policy)

	validateManager := NewSimpleManager()
	validateManager.FileSeeker = fs
	validator := NewValidator()
	validator.Time = time.Now().UTC()
	validateManager.Validator = validator
	validateManager.AddInitial([]*PKIFile{
		&PKIFile{
			Path: talPath,
			Type: TYPE_TAL,
		},
	})

	// Manifest
	manifestContent := librpki.ManifestContent{
		ManifestNumber: big.NewInt(14562123),
		ThisUpdate:     time.Now().UTC(),
		NextUpdate:     time.Now().UTC().Add(time.Hour * 48),
		FileHashAlg:    librpki.SHA256OID,
		FileList: []librpki.FileList{
			librpki.FileList{
				File: "test.cer",
				Hash: asn1.BitString{
					Bytes:     orghash[:],
					BitLength: 256,
				},
			},
			librpki.FileList{
				File: "root.crl",
				Hash: asn1.BitString{
					Bytes:     orghash[:],
					BitLength: 256,
				},
			},
		},
	}
	manifestContentEnc, _ := librpki.EncodeManifestContent(manifestContent)

	manifestCms, _ := librpki.EncodeCMS(nil, manifestContentEnc, genTime)

	manifestCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(55555),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Manifest",
		},
		NotBefore:      genTime,
		NotAfter:       genTime.Add(validity),
		SubjectKeyId:   skiPublicKey[MANIFEST_KEY_INDEX_1],
		AuthorityKeyId: skiPublicKey[ROOT_KEY_INDEX],
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			*policy,
			*ipblocksExtension2,
			*parentPath,
			*manifestPath,
			*asnExtension2,
		},
		CRLDistributionPoints: []string{"rsync://lambda/module/root.crl"},
	}
	certBytesMft2, _ := x509.CreateCertificate(
		rand.Reader, manifestCert, rootCert, publicKeys[MANIFEST_KEY_INDEX_1], keys[ROOT_KEY_INDEX])

	encap, _ := librpki.ManifestToEncap(manifestContentEnc)

	manifestCms.Sign(
		rand.Reader, skiPublicKey[MANIFEST_KEY_INDEX_1],
		encap, keys[MANIFEST_KEY_INDEX_1],
		certBytesMft2)

	cmsBytes, _ := asn1.Marshal(*manifestCms)
	fs.AddFile("rsync://lambda/module/root.mft", cmsBytes)

	return &TestManager{
		fs:            fs,
		keys:          keys,
		publicKeys:    publicKeys,
		skiPublicKey:  skiPublicKey,
		tal:           tal,
		talPath:       talPath,
		rootCert:      rootCert,
		orgCert:       orgCert,
		pathExtension: pathExtension,
		orgHash:       orghash,
		crlHash:       crlhash,
		validatorManager:validateManager,
	}
}

func addROAToManifest(manager *TestManager, cmsBytes []byte) {

	manager.fs.AddFile("rsync://lambda/module/certs/test.roa", cmsBytes)
	roahash := sha256.Sum256(cmsBytes)
	manifestContent := librpki.ManifestContent{
		ManifestNumber: big.NewInt(7845),
		ThisUpdate:     time.Now().UTC(),
		NextUpdate:     time.Now().UTC(),
		FileHashAlg:    librpki.SHA256OID,
		FileList: []librpki.FileList{
			librpki.FileList{
				File: "test.roa",
				Hash: asn1.BitString{
					Bytes:     roahash[:],
					BitLength: 256,
				},
			},
			librpki.FileList{
				File: "test.crl",
				Hash: asn1.BitString{
					Bytes:     manager.crlHash[:],
					BitLength: 256,
				},
			},
		},
	}
	manifestContentEnc, _ := librpki.EncodeManifestContent(manifestContent)

	genTime := time.Now().UTC()
	validity := time.Duration(time.Hour * 24 * 365 * 10)
	manifestCms, _ := librpki.EncodeCMS(nil, manifestContentEnc, genTime)

	manifestCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(6542),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Manifest2",
		},
		NotBefore:      genTime,
		NotAfter:       genTime.Add(validity),
		SubjectKeyId:   manager.skiPublicKey[MANIFEST_KEY_INDEX_2],
		AuthorityKeyId: manager.skiPublicKey[SUBCERT_KEY_INDEX],
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			*manager.pathExtension[POLIC_EXTENSION],
			*manager.pathExtension[IP_BLOCK_EXTENSION_2],
			*manager.pathExtension[SUBCERT_KEY_INDEX],
			*manager.pathExtension[MANIFEST_KEY_INDEX_2],
			*manager.pathExtension[ASN_EXTENSION_2],
		},
		CRLDistributionPoints: []string{"rsync://lambda/module/certs/test.crl"},
	}
	certBytesMft, _ := x509.CreateCertificate(
		rand.Reader, manifestCert, manager.orgCert,
		manager.publicKeys[MANIFEST_KEY_INDEX_2],
		manager.keys[SUBCERT_KEY_INDEX])

	encap, _ := librpki.ManifestToEncap(manifestContentEnc)

	manifestCms.Sign(rand.Reader,
		manager.skiPublicKey[MANIFEST_KEY_INDEX_2],
		encap, manager.keys[MANIFEST_KEY_INDEX_2], certBytesMft)

	cmsManifestBytes, _ := asn1.Marshal(*manifestCms)

	manager.fs.AddFile("rsync://lambda/module/certs/test.mft", cmsManifestBytes)
}

func signROA(manager *TestManager) ([]byte, error) {
	genTime := time.Now().UTC()
	validity := time.Duration(time.Hour * 24 * 365 * 10)
	_, prefix, _ := net.ParseCIDR("10.0.0.0/24")
	roaContent := []*librpki.ROA_Entry{
		&librpki.ROA_Entry{
			IPNet:     prefix,
			MaxLength: 24,
		},
	}
	roaContentEnc, _ := librpki.EncodeROAEntries(65001, roaContent)
	roaCms, _ := librpki.EncodeCMS(nil, roaContentEnc, genTime)

	roaCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(4453),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-ROA",
		},
		ExtraExtensions: []pkix.Extension{
			*manager.pathExtension[POLIC_EXTENSION],
			*manager.pathExtension[IP_BLOCK_EXTENSION_1],
			*manager.pathExtension[ROOT_KEY_INDEX],
			*manager.pathExtension[ROA_KEY_INDEX],
		},
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
		SubjectKeyId:          manager.skiPublicKey[ROA_KEY_INDEX],
		KeyUsage:              x509.KeyUsageDigitalSignature,
		AuthorityKeyId:        manager.skiPublicKey[SUBCERT_KEY_INDEX],
		CRLDistributionPoints: []string{"rsync://lambda/module/certs/test.crl"},
	}
	certBytesRoa, _ := x509.CreateCertificate(
		rand.Reader, roaCert, manager.orgCert, manager.publicKeys[ROA_KEY_INDEX], manager.keys[SUBCERT_KEY_INDEX])

	encap, _ := librpki.ROAToEncap(roaContentEnc)

	_ = roaCms.Sign(rand.Reader,
		manager.skiPublicKey[ROA_KEY_INDEX],
		encap, manager.keys[ROA_KEY_INDEX],
		certBytesRoa)

	// test for cmsbyte output
	return asn1.Marshal(*roaCms)
}

//



func validateROA(manager *TestManager) int {
	manager.validatorManager.Explore(false, false)
	var count int
	for _, roa := range manager.validatorManager.Validator.ValidROA {
		d := roa.Resource.(*librpki.RPKI_ROA)
		count += len(d.Valids)
	}
	return count
}

func BenchmarkSignROACertification(b *testing.B) {
	manager := NewTestManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signROA(manager)
	}
}

func TestValidateROACertification(t *testing.T) {
	manager := NewTestManager()
	roa, _ := signROA(manager)
	addROAToManifest(manager, roa)
	count := validateROA(manager)
	if count != 1{
		t.Errorf("validate fail != %d", count)
	}
}

func BenchmarkValidateROACertification(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		manager := NewTestManager()
		roa, _ := signROA(manager)
		addROAToManifest(manager, roa)
		b.StartTimer()
		validateROA(manager)
	}
}
