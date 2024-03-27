package certwatcher

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"
)

func GenerateTLSCertificateRequest(dnsNames []string) (*x509.CertificateRequest, *ecdsa.PrivateKey, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ipAddresses := make([]net.IP, 0)

	for _, dnsName := range dnsNames {
		// resolve dns name to ip address
		ips, err := net.LookupIP(dnsName)

		if err != nil {
			fmt.Printf("Error resolving dns name %s %v\n", dnsName, err)
			return nil, nil, err
		}

		ipAddresses = append(ipAddresses, ips...)
	}

	// remove duplicates on ip addresses
	seen := make(map[string]bool)
	uniqIPAddresses := make([]net.IP, 0)

	for _, ip := range ipAddresses {
		if _, ok := seen[ip.String()]; !ok {
			seen[ip.String()] = true
			uniqIPAddresses = append(uniqIPAddresses, ip)
		}
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "TLS Certificate",
			Organization: []string{"Local Cert Manager"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:           dnsNames,
		IPAddresses:        uniqIPAddresses,
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)

	if err != nil {
		fmt.Printf("Error creating certificate request %v\n", err)
		return nil, nil, err
	}

	certReq, err := x509.ParseCertificateRequest(derBytes)

	if err != nil {
		fmt.Printf("Error parsing certificate request %v\n", err)
		return nil, nil, err
	}

	return certReq, key, nil
}

type CertificateWatcher interface {
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
	Start() error
	Stop()
}

type certificateWatcher struct {
	certManagerUrl    string
	domains           []string
	caFile            string
	sync              sync.RWMutex
	currentCertifcate *tls.Certificate
	privateKey        *ecdsa.PrivateKey
	ticker            *time.Ticker
}

func NewCertificateWatcher(certManagerUrl, caFile string, domains []string) CertificateWatcher {

	// remove duplicates on ip addresses
	seen := make(map[string]bool)
	uniqDomains := make([]string, 0)

	for _, domain := range domains {
		if _, ok := seen[domain]; !ok {
			seen[domain] = true
			uniqDomains = append(uniqDomains, domain)
		}
	}

	return &certificateWatcher{certManagerUrl: certManagerUrl, caFile: caFile, domains: uniqDomains}
}

func (cw *certificateWatcher) Start() error {
	cw.ticker = time.NewTicker(time.Minute * 1)

	err := cw.obtainCertificate()

	if err != nil {
		return err
	}

	go func() {
		for range cw.ticker.C {
			err := cw.obtainCertificate()

			if err != nil {
				fmt.Printf("Error obtaining certificate %v\n", err)
			}

		}
	}()

	return nil
}

func (cw *certificateWatcher) Stop() {
	cw.ticker.Stop()
}

func (cw *certificateWatcher) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cw.sync.RLock()
	defer cw.sync.RUnlock()

	if cw.currentCertifcate == nil {
		fmt.Printf("No certificate available\n")
		return nil, fmt.Errorf("no certificate available")
	}

	return cw.currentCertifcate, nil
}

func (cw *certificateWatcher) obtainCertificate() error {
	cw.sync.Lock()
	defer cw.sync.Unlock()

	if cw.currentCertifcate != nil {
		// check if certificate is still valid
		// if valid return
		// else renew

		cert := cw.currentCertifcate.Leaf

		if cert == nil {
			// need to parse certificate
			var err error
			cert, err = x509.ParseCertificate(cw.currentCertifcate.Certificate[0])

			if err != nil {
				fmt.Printf("Error parsing certificate %v\n", err)
			} else {
				cw.currentCertifcate.Leaf = cert
			}
		}

		if cert != nil {
			now := time.Now()

			// find half of the certificate validity period
			// if now + half of the validity period is before expiry
			// then it is valid
			// else renew

			diff := cert.NotAfter.Sub(cert.NotBefore)
			half := diff / 2

			if now.Add(half).Before(cert.NotAfter) {
				fmt.Printf("Certificate is still valid\n")
				return nil
			} else {
				fmt.Printf("Certificate need renew\n")
			}

		} else {
			fmt.Printf("Certificate is nil\n")
		}
	}

	certReq, key, err := GenerateTLSCertificateRequest(cw.domains)

	if err != nil {
		fmt.Printf("Error generating certificate request %v\n", err)
		return err
	}

	cw.privateKey = key

	cert, err := cw.getCertificateFromCertManager(cw.certManagerUrl, cw.caFile, certReq)

	if err != nil {
		fmt.Printf("Error getting certificate from cert manager %v\n", err)
		return err
	}

	cw.currentCertifcate = cert

	fmt.Printf("Certificate renewed\n")

	return nil
}

func (cw *certificateWatcher) getCertificateFromCertManager(certManagerUrl, caPath string, certReq *x509.CertificateRequest) (*tls.Certificate, error) {
	// send certificate request to cert manager
	// get certificate back
	// return certificate

	// encode certificate request to PEM

	pemCertReq := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certReq.Raw,
	})

	if pemCertReq == nil {
		panic("error encoding certificate request to PEM")
	}

	certPool, err := x509.SystemCertPool()

	if err != nil {
		panic(err)
	}

	if caCertPEM, err := ioutil.ReadFile(cw.caFile); err != nil {
		panic(err)
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("invalid cert in CA PEM")
	}

	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{Transport: tr}

	fmt.Printf("Sending certificate request to %s\n", certManagerUrl)

	resp, err := client.Post(certManagerUrl, "application/x-pem-certificate-request", bytes.NewReader(pemCertReq))

	if err != nil {
		fmt.Printf("Post failed to %s %v\n", certManagerUrl, err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/x-pem-file" {
		return nil, fmt.Errorf("unexpected content type %s", resp.Header.Get("Content-Type"))
	}

	certData, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		fmt.Printf("Error reading certificate response %v\n", err)
		return nil, err
	}

	certBlock, _ := pem.Decode(certData)

	cert, err := x509.ParseCertificate(certBlock.Bytes)

	if err != nil {
		fmt.Printf("Error parsing certificate response %v\n", err)
		return nil, err
	}

	fmt.Printf("Certificate obtained\n")

	// merge certificate and private key into tls certificate
	// return tls certificate

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  cw.privateKey,
	}

	return &tlsCert, nil
}
