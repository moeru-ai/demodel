package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/nekomeowww/xo"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"github.com/smallstep/truststore"
)

func mapWithFormat[R any](format string) func(error) (R, error) {
	return func(err error) (R, error) {
		var empty R
		return empty, fmt.Errorf(format, err)
	}
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return mo.TupleToResult(rand.Int(rand.Reader, serialNumberLimit)).MapErr(mapWithFormat[*big.Int]("failed to generate serial number: %w")).MustGet()
}

func main() {
	useECDSA := os.Getenv("DEMODEL_PROXY_CA_USE_ECDSA")

	var privateKey crypto.PrivateKey

	if useECDSA == "true" || useECDSA == "1" {
		privateKey = lo.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	} else {
		privateKey = lo.Must(rsa.GenerateKey(rand.Reader, 4095))
	}

	cryptoSignerFromPrivateKey, ok := privateKey.(crypto.Signer)
	if !ok {
		panic("private key is not a crypto.Signer")
	}

	publicKey := cryptoSignerFromPrivateKey.Public()

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
		IsCA:      true,
		NotBefore: time.Now(),
		NotAfter:  expiration,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER := mo.
		TupleToResult(x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)).
		MapErr(mapWithFormat[[]byte]("failed to create certificate: %w")).
		MustGet()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privateDER := mo.
		TupleToResult(x509.MarshalPKCS8PrivateKey(privateKey)).
		MapErr(mapWithFormat[[]byte]("failed to marshal private key: %w")).
		MustGet()
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	lo.Must0(os.WriteFile("demodel-proxy-ca.crt", certPEM, 0644), "failed to write certificate file")
	lo.Must0(os.WriteFile("demodel-proxy-ca.key", privatePEM, 0600), "failed to write private key file")

	lo.Must0(truststore.InstallFile(xo.RelativePathBasedOnPwdOf("demodel-proxy-ca.crt")))
}
