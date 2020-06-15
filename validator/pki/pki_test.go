package pki

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net"
	"testing"
	"time"
	//"fmt"

	"github.com/cloudflare/cfrpki/validator/lib"
)

func TestPKI(t *testing.T) {
	fs := NewFileSeeker()

	t.Logf("Creating keys\n")
	keys := CreateKeys()

	privkeyRoot := keys[0]
	pubkeyRoot := privkeyRoot.Public()

	privkeyManifest := keys[1]
	pubkeyManifest := privkeyManifest.Public()

	privkeyManifest2 := keys[2]
	pubkeyManifest2 := privkeyManifest2.Public()

	privkeyRoa := keys[3]
	pubkeyRoa := privkeyRoa.Public()

	privkeySubCert := keys[4]
	pubkeySubCert := privkeySubCert.Public()

	skiRoot, err := librpki.HashPublicKey(pubkeyRoot)
	assert.Nil(t, err)
	skiManifest, err := librpki.HashPublicKey(pubkeyManifest)
	assert.Nil(t, err)
	skiManifest2, err := librpki.HashPublicKey(pubkeyManifest2)
	assert.Nil(t, err)
	skiROA, err := librpki.HashPublicKey(pubkeyRoa)
	assert.Nil(t, err)
	skiSubCert, err := librpki.HashPublicKey(pubkeySubCert)
	assert.Nil(t, err)

	genTime := time.Now().UTC()
	validity := time.Duration(time.Hour * 24 * 365 * 10)

	// TAL
	t.Logf("Creating TAL\n")

	tal, err := librpki.CreateTAL("rsync://lambda/module/root.cer", privkeyRoot.Public())
	assert.Nil(t, err)
	data, err := librpki.EncodeTAL(tal)
	assert.Nil(t, err)

	talPath := "rsync://lambda/module/example.tal"
	fs.AddFile(talPath, data)

	// CERT
	t.Logf("Creating certificates\n")
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
	ipblocksExtension, err := librpki.EncodeIPAddressBlock(ipBlocks)
	ipBlocks2 := []librpki.IPCertificateInformation{
		&librpki.IPAddressNull{
			Family: 1,
		},
	}
	ipblocksExtension2, err := librpki.EncodeIPAddressBlock(ipBlocks2)
	assert.Nil(t, err)

	parentPath, err := librpki.EncodeInfoAccess(true, "rsync://lambda/module/root.cer")
	assert.Nil(t, err)
	manifestPath, err := librpki.EncodeInfoAccess(false, "rsync://lambda/module/root.mft")
	assert.Nil(t, err)
	manifestPath2, err := librpki.EncodeInfoAccess(false, "rsync://lambda/module/certs/test.mft")
	assert.Nil(t, err)
	roaPath, err := librpki.EncodeInfoAccess(false, "rsync://lambda/module/certs/test.roa")
	assert.Nil(t, err)
	parentSubPath, err := librpki.EncodeInfoAccess(true, "rsync://lambda/module/test.cer")
	assert.Nil(t, err)

	policy, err := librpki.EncodePolicyInformation("http://example.com/cps.html")
	assert.Nil(t, err)

	asnsBlock := []librpki.ASNCertificateInformation{
		&librpki.ASNRange{
			Min: 0,
			Max: 4294967295,
		},
	}
	asnExtension, err := librpki.EncodeASN(asnsBlock, nil)
	assert.Nil(t, err)
	asnsBlock2 := []librpki.ASNCertificateInformation{
		&librpki.ASNull{},
	}
	asnExtension2, err := librpki.EncodeASN(asnsBlock2, nil)
	assert.Nil(t, err)

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
	siaExtension, err := librpki.EncodeSIA(sias)
	assert.Nil(t, err)

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
	siaExtensionSub, err := librpki.EncodeSIA(siasSub)
	assert.Nil(t, err)

	t.Logf("Creating root certificate\n")
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
		SubjectKeyId:          skiRoot,
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
	}

	certBytesRoot, err := x509.CreateCertificate(rand.Reader, rootCert, rootCert, pubkeyRoot, privkeyRoot)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/root.cer", certBytesRoot)

	// CRL
	t.Logf("Creating CRL\n")
	crlBytes, err := librpki.CreateCRL(rootCert, rand.Reader, privkeyRoot, []pkix.RevokedCertificate{}, genTime, genTime.Add(validity), big.NewInt(1))
	assert.Nil(t, err)

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
		AuthorityKeyId:        skiRoot,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skiSubCert,
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
		CRLDistributionPoints: []string{"rsync://lambda/module/root.crl"},
	}
	// 签名者私钥，以及被签名者的公钥信息　这里使用root证书来完成SubCert证书的签名
	certBytesOrg, err := x509.CreateCertificate(rand.Reader, orgCert, rootCert, pubkeySubCert, privkeyRoot)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/test.cer", certBytesOrg)

	orghash := sha256.Sum256(certBytesOrg)

	// CRL
	crlBytes, err = librpki.CreateCRL(orgCert, rand.Reader, privkeySubCert, []pkix.RevokedCertificate{}, genTime, genTime.Add(validity), big.NewInt(1))
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/certs/test.crl", crlBytes)
	crlhash := sha256.Sum256(crlBytes)

	// ROA
	t.Logf("Creating ROAs\n")
	_, prefix, _ := net.ParseCIDR("10.0.0.0/24")
	roaContent := []*librpki.ROA_Entry{
		&librpki.ROA_Entry{
			IPNet:     prefix,
			MaxLength: 24,
		},
	}
	roaContentEnc, err := librpki.EncodeROAEntries(65001, roaContent)
	assert.Nil(t, err)

	roaCms, err := librpki.EncodeCMS(nil, roaContentEnc, genTime)
	assert.Nil(t, err)

	roaCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(4453),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-ROA",
		},
		ExtraExtensions: []pkix.Extension{
			*policy,
			*ipblocksExtension,
			*parentSubPath,
			*roaPath,
		},
		NotBefore:             genTime,
		NotAfter:              genTime.Add(validity),
		SubjectKeyId:          skiROA,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		AuthorityKeyId:        skiSubCert,
		CRLDistributionPoints: []string{"rsync://lambda/module/certs/test.crl"},
	}
	certBytesRoa, err := x509.CreateCertificate(rand.Reader, roaCert, orgCert, pubkeyRoa, privkeySubCert)
	assert.Nil(t, err)

	encap, err := librpki.ROAToEncap(roaContentEnc)
	assert.Nil(t, err)
	err = roaCms.Sign(rand.Reader, skiROA, encap, privkeyRoa, certBytesRoa)
	assert.Nil(t, err)

	cmsBytes, err := asn1.Marshal(*roaCms)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/certs/test.roa", cmsBytes)

	roahash := sha256.Sum256(cmsBytes)

	// Manifest Organization
	t.Logf("Creating manifest\n")
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
					Bytes:     crlhash[:],
					BitLength: 256,
				},
			},
		},
	}
	manifestContentEnc, err := librpki.EncodeManifestContent(manifestContent)
	assert.Nil(t, err)

	manifestCms, err := librpki.EncodeCMS(nil, manifestContentEnc, genTime)
	assert.Nil(t, err)

	manifestCert := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(6542),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Manifest2",
		},
		NotBefore:      genTime,
		NotAfter:       genTime.Add(validity),
		SubjectKeyId:   skiManifest2,
		AuthorityKeyId: skiSubCert,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			*policy,
			*ipblocksExtension2,
			*parentSubPath,
			*manifestPath2,
			*asnExtension2,
		},
		CRLDistributionPoints: []string{"rsync://lambda/module/certs/test.crl"},
	}
	certBytesMft, err := x509.CreateCertificate(rand.Reader, manifestCert, orgCert, pubkeyManifest2, privkeySubCert)
	assert.Nil(t, err)

	encap, err = librpki.ManifestToEncap(manifestContentEnc)
	assert.Nil(t, err)
	err = manifestCms.Sign(rand.Reader, skiManifest2, encap, privkeyManifest2, certBytesMft)
	assert.Nil(t, err)

	cmsBytes, err = asn1.Marshal(*manifestCms)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/certs/test.mft", cmsBytes)

	// Manifest
	manifestContent = librpki.ManifestContent{
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
	manifestContentEnc, err = librpki.EncodeManifestContent(manifestContent)
	assert.Nil(t, err)

	manifestCms, err = librpki.EncodeCMS(nil, manifestContentEnc, genTime)
	assert.Nil(t, err)

	manifestCert = &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(55555),
		Subject: pkix.Name{
			CommonName: "OctoRPKI-Manifest",
		},
		NotBefore:      genTime,
		NotAfter:       genTime.Add(validity),
		SubjectKeyId:   skiManifest,
		AuthorityKeyId: skiRoot,
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
	certBytesMft2, err := x509.CreateCertificate(rand.Reader, manifestCert, rootCert, pubkeyManifest, privkeyRoot)
	assert.Nil(t, err)

	encap, err = librpki.ManifestToEncap(manifestContentEnc)
	assert.Nil(t, err)
	err = manifestCms.Sign(rand.Reader, skiManifest, encap, privkeyManifest, certBytesMft2)
	assert.Nil(t, err)

	cmsBytes, err = asn1.Marshal(*manifestCms)
	assert.Nil(t, err)

	fs.AddFile("rsync://lambda/module/root.mft", cmsBytes)

	t.Logf("Validating\n")
	count := Validate(talPath, fs)
	assert.Equal(t, 1, count)
}
