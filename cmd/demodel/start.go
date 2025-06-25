package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"github.com/spf13/cobra"
)

type CertStorage struct {
	rootCA              *tls.Certificate
	rootCACertPEM       []byte
	rootCAPrivateKeyPEM []byte

	rootCACert       *x509.Certificate
	rootCAPrivateKey crypto.Signer

	useECDSA bool

	certs map[string]*tls.Certificate
	mtx   sync.RWMutex
}

func (cs *CertStorage) Fetch(hostname string, _ func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	cs.mtx.RLock()
	cert, ok := cs.certs[hostname]
	cs.mtx.RUnlock()
	if ok {
		return cert, nil
	}

	var privateKey crypto.PrivateKey

	if cs.useECDSA {
		privateKey = lo.Must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	} else {
		privateKey = lo.Must(rsa.GenerateKey(rand.Reader, 4095))
	}

	cryptoSignerFromPrivateKey, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
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
			CommonName:         hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	template.DNSNames = []string{hostname}

	hostCertDER := mo.
		TupleToResult(x509.CreateCertificate(rand.Reader, template, cs.rootCACert, publicKey, cs.rootCAPrivateKey)).
		MapErr(mapWithFormat[[]byte]("failed to create certificate: %w"))
	if hostCertDER.IsError() {
		return nil, hostCertDER.Error()
	}

	hostCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hostCertDER.MustGet()})

	privateDER := mo.
		TupleToResult(x509.MarshalPKCS8PrivateKey(privateKey)).
		MapErr(mapWithFormat[[]byte]("failed to marshal private key: %w"))
	if privateDER.IsError() {
		return nil, privateDER.Error()
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER.MustGet()})

	load, err := tls.X509KeyPair(hostCertPEM, privatePEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	cert = &tls.Certificate{
		Certificate: load.Certificate,
		PrivateKey:  privateKey,
		Leaf:        template,
	}

	cs.mtx.Lock()
	cs.certs[hostname] = cert
	cs.mtx.Unlock()

	return cert, nil
}

func NewCertStorage(
	rootCA *tls.Certificate,
	rootCACertPEM []byte,
	rootCAPrivateKeyPEM []byte,
	useECDSA bool,
) mo.Result[*CertStorage] {
	block, _ := pem.Decode(rootCACertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return mo.Err[*CertStorage](errors.New("failed to decode root CA certificate PEM"))
	}

	rootCACert := mo.TupleToResult(x509.ParseCertificate(block.Bytes)).MapErr(mapWithFormat[*x509.Certificate]("failed to parse root CA certificate: %w"))
	if rootCACert.IsError() {
		return mo.Err[*CertStorage](rootCACert.Error())
	}

	block, _ = pem.Decode(rootCAPrivateKeyPEM)
	if block == nil || (block.Type != "PRIVATE KEY") {
		return mo.Err[*CertStorage](errors.New("failed to decode root CA private key PEM"))
	}

	rootCAPrivateKey := mo.TupleToResult(x509.ParsePKCS8PrivateKey(block.Bytes)).MapErr(mapWithFormat[any]("failed to parse root CA private key: %w"))
	if rootCAPrivateKey.IsError() {
		return mo.Err[*CertStorage](rootCAPrivateKey.Error())
	}

	signer, ok := rootCAPrivateKey.MustGet().(crypto.Signer)
	if !ok {
		return mo.Err[*CertStorage](errors.New("root CA private key does not implement crypto.Signer"))
	}

	return mo.Ok(&CertStorage{
		rootCA:              rootCA,
		rootCACertPEM:       rootCACertPEM,
		rootCAPrivateKeyPEM: rootCAPrivateKeyPEM,
		rootCACert:          rootCACert.MustGet(),
		rootCAPrivateKey:    signer,
		useECDSA:            useECDSA,
		certs:               make(map[string]*tls.Certificate),
	})
}

func start() {
	caResult := readOrNewCA(configurationUseECDSA)

	tlsCert := mo.
		TupleToResult(tls.X509KeyPair(caResult.MustGet().certificate, caResult.MustGet().privateKey)).
		MapErr(mapWithFormat[tls.Certificate]("failed to load certificate and private key: %w")).
		MustGet()

	handler := goproxy.NewProxyHttpServer()
	handler.CertStore = NewCertStorage(
		&tlsCert,
		caResult.MustGet().certificate,
		caResult.MustGet().privateKey,
		configurationUseECDSA,
	).MustGet()

	handler.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		if configurationMitMAll {
			return goproxy.MitmConnect, host
		}
		if configurationNoMitM {
			return nil, ""
		}

		if lo.Contains(hosts, host) {
			return goproxy.MitmConnect, host
		}

		return nil, ""
	})
	handler.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		fmt.Println(req.RequestURI, req.Method, req.Header.Get("User-Agent"))
		return req, nil
	})
	handler.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		fmt.Println(resp.Request.RequestURI, resp.Request.Method, resp.Header.Get("User-Agent"), resp.Status, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Length"))
		return resp
	})

	ln := lo.Must(net.Listen("tcp", ":8080"))

	fmt.Fprintf(os.Stderr, "Starting demodel server on %s\n", ln.Addr().String())

	server := &http.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
		Handler:   handler,
	}

	lo.Must0(server.Serve(ln))
}

func subCommandStart() *cobra.Command {
	command := &cobra.Command{
		Use:   "start",
		Short: "Start the demodel server",
		Long:  "Start the demodel server, serve for incoming traffic and handle requests.",
		RunE: func(cmd *cobra.Command, args []string) error {
			start()
			return nil
		},
	}

	return command
}
