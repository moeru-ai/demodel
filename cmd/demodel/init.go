package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/adrg/xdg"
	"github.com/nekomeowww/xo"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"github.com/smallstep/truststore"
	"github.com/spf13/cobra"
)

type ca struct {
	certificate []byte
	privateKey  []byte
}

func readOrNewCA(useECDSA bool) mo.Result[ca] {
	certFilePath := mo.TupleToResult(xdg.DataFile("certificates/demodel-ca.crt")).
		MapErr(mapWithFormat[string]("failed to get data file path for storing certificates: %w")).
		MustGet()

	privateKeyFilePath := mo.TupleToResult(xdg.DataFile("certificates/demodel-ca.pem")).
		MapErr(mapWithFormat[string]("failed to get data file path for storing certificates: %w")).
		MustGet()

	{
		certPEM := mo.TupleToResult(os.ReadFile(certFilePath)).MapErr(mapWithFormat[[]byte]("failed to read certificate file: %w"))
		if certPEM.IsError() {
			if !errors.Is(certPEM.Error(), os.ErrNotExist) {
				return mo.Err[ca](certPEM.Error())
			}
		}

		privatePEM := mo.TupleToResult(os.ReadFile(privateKeyFilePath)).MapErr(mapWithFormat[[]byte]("failed to read private key file: %w"))
		if privatePEM.IsError() {
			if !errors.Is(privatePEM.Error(), os.ErrNotExist) {
				return mo.Err[ca](privatePEM.Error())
			}
		}

		if !certPEM.IsError() && !privatePEM.IsError() {
			// If both files exist, return the existing CA
			return mo.Ok(ca{
				certificate: certPEM.MustGet(),
				privateKey:  privatePEM.MustGet(),
			})
		}
	}

	var privateKey crypto.PrivateKey

	if useECDSA {
		privateKey = lo.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	} else {
		privateKey = lo.Must(rsa.GenerateKey(rand.Reader, 4095))
	}

	cryptoSignerFromPrivateKey, ok := privateKey.(crypto.Signer)
	if !ok {
		return mo.Err[ca](errors.New("private key does not implement crypto.Signer"))
	}

	publicKey := cryptoSignerFromPrivateKey.Public()

	spkiASN1 := mo.TupleToResult(x509.MarshalPKIXPublicKey(publicKey)).
		MapErr(mapWithFormat[[]byte]("failed to marshal public key: %w")).
		MustGet()

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	_ = mo.TupleToResult(asn1.Unmarshal(spkiASN1, &spki)).
		MapErr(mapWithFormat[[]byte]("failed to unmarshal SPKI: %w")).
		MustGet()

	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)

	// From https://github.com/FiloSottile/mkcert/blob/1c1dc4ed27ed5936046b6398d39cab4d657a2d8e/cert.go#L59C2-L62C43
	//
	// Certificates last for 2 years and 3 months, which is always less than
	// 825 days, the limit that macOS/iOS apply to all certificates,
	// including custom roots. See https://support.apple.com/en-us/HT210176.
	expiration := time.Now().AddDate(2, 3, 0)

	template := &x509.Certificate{
		SerialNumber: randomSerialNumber(),
		Subject: pkix.Name{
			Organization:       []string{"Moeru AI (https://github.com/moeru-ai)"},
			OrganizationalUnit: []string{"Demodel (https://github.com/moeru-ai/demodel)"},
			CommonName:         "Demodel Cache Proxy CA",
		},
		SubjectKeyId:          skid[:],
		NotBefore:             time.Now(),
		NotAfter:              expiration,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	certDER := mo.
		TupleToResult(x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)).
		MapErr(mapWithFormat[[]byte]("failed to create certificate: %w"))
	if certDER.IsError() {
		return mo.Err[ca](certDER.Error())
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER.MustGet()})

	privateDER := mo.
		TupleToResult(x509.MarshalPKCS8PrivateKey(privateKey)).
		MapErr(mapWithFormat[[]byte]("failed to marshal private key: %w"))
	if privateDER.IsError() {
		return mo.Err[ca](privateDER.Error())
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER.MustGet()})

	res := mo.TupleToResult[any](nil, os.WriteFile(certFilePath, certPEM, 0644)).MapErr(mapWithFormat[any]("failed to write certificate file: %w"))
	if res.IsError() {
		return mo.Err[ca](res.Error())
	}

	res = mo.TupleToResult[any](nil, os.WriteFile(privateKeyFilePath, privatePEM, 0600)).MapErr(mapWithFormat[any]("failed to write private key file: %w"))
	if res.IsError() {
		return mo.Err[ca](res.Error())
	}

	install := mo.TupleToResult[any](nil, truststore.InstallFile(xo.RelativePathBasedOnPwdOf("demodel-proxy-ca.crt")))
	if install.IsError() {
		return mo.Err[ca](install.Error())
	}

	return mo.Ok(ca{
		certificate: certPEM,
		privateKey:  privatePEM,
	})
}

func subCommandInit() *cobra.Command {
	command := &cobra.Command{
		Use:   "init",
		Short: "Initialize the demodel server and create necessary directories and files.",
		Long:  "Initialize the demodel server and create necessary directories and files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = readOrNewCA(configurationUseECDSA)
			return nil
		},
	}

	return command
}
