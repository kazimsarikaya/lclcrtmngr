package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/kazimsarikaya/lclcrtmngr/pkg/certwatcher"
)

func GenerateTLSCertificate(certReq *x509.CertificateRequest, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, certValidDuration time.Duration) (*x509.Certificate, error) {
	if err := certReq.CheckSignature(); err != nil {
		fmt.Printf("Certificate request signature is invalid\n")
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))

	if err != nil {
		return nil, err
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber:            serialNumber,
		RawSubject:              certReq.RawSubject,
		RawSubjectPublicKeyInfo: certReq.RawSubjectPublicKeyInfo,
		NotBefore:               now,
		NotAfter:                now.Add(certValidDuration),
		SignatureAlgorithm:      x509.ECDSAWithSHA256,
		PublicKeyAlgorithm:      x509.ECDSA,
		PublicKey:               certReq.PublicKey,
		Signature:               certReq.Signature,
		DNSNames:                certReq.DNSNames,
		EmailAddresses:          certReq.EmailAddresses,
		IPAddresses:             certReq.IPAddresses,
		URIs:                    certReq.URIs,
		KeyUsage:                x509.KeyUsageDigitalSignature,
		ExtKeyUsage:             []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                    false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certReq.PublicKey, caKey)

	if err != nil {
		fmt.Printf("Error creating certificate %v\n", err)
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)

	if err != nil {
		fmt.Printf("Error parsing certificate %v\n", err)
		return nil, err

	}

	return cert, nil
}

func ConvertCertificateToPEM(cert *x509.Certificate) []byte {
	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	return certData
}

type certManager struct {
	sync              sync.RWMutex
	caName            string
	caCertFile        string
	caKeyFile         string
	managerDomains    []string
	certValidDuration time.Duration
	caCert            *x509.Certificate
	caPrivateKey      *ecdsa.PrivateKey
	privateKey        *ecdsa.PrivateKey
	tlsCert           *tls.Certificate
	ticker            *time.Ticker
}

func NewCertificateManager(caName, caCertFile, caKeyFile string, managerDomains []string, certValidDuration time.Duration) *certManager {
	return &certManager{caName: caName, caCertFile: caCertFile, caKeyFile: caKeyFile, managerDomains: managerDomains, certValidDuration: certValidDuration}
}

func (cm *certManager) Start() error {
	err := cm.loadCA()

	if err != nil {
		return err
	}

	err = cm.renewTLSCertificate()

	if err != nil {
		return err
	}

	cm.ticker = time.NewTicker(time.Minute * 1)

	go func() {
		for range cm.ticker.C {
			cm.sync.Lock()
			err := cm.renewTLSCertificate()

			if err != nil {
				fmt.Printf("Error renewing certificate %v\n", err)
			}

			cm.sync.Unlock()
		}
	}()

	return nil
}

func (cm *certManager) renewTLSCertificate() error {
	if cm.tlsCert != nil {
		// check if certificate is still valid
		// if valid return
		// else renew

		cert := cm.tlsCert.Leaf

		if cert == nil {
			// need to parse certificate
			var err error
			cert, err = x509.ParseCertificate(cm.tlsCert.Certificate[0])

			if err != nil {
				fmt.Printf("Error parsing certificate %v\n", err)
			} else {
				cm.tlsCert.Leaf = cert
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

	tlsCertReq, tlsKey, err := certwatcher.GenerateTLSCertificateRequest(cm.managerDomains)

	if err != nil {
		return err
	}

	tlsCert, err := GenerateTLSCertificate(tlsCertReq, cm.caCert, cm.caPrivateKey, cm.certValidDuration)

	if err != nil {
		return err
	}

	cm.tlsCert = &tls.Certificate{
		Certificate: [][]byte{tlsCert.Raw},
		PrivateKey:  tlsKey,
	}

	fmt.Printf("Renewed TLS certificate\n")

	return nil
}

func (cm *certManager) Stop() {
	cm.ticker.Stop()
}

func (cm *certManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.sync.RLock()
	defer cm.sync.RUnlock()

	return cm.tlsCert, nil
}

func (cm *certManager) readKeyOrCreateAndReadKey() error {
	if !fileExists(cm.caKeyFile) {
		fmt.Printf("Key file %s does not exist, creating\n", cm.caKeyFile)

		err := cm.createKeyFile()

		if err != nil {
			return err
		}
	}

	keyData, err := ioutil.ReadFile(cm.caKeyFile)

	if err != nil {
		fmt.Printf("Error reading key file %s %v\n", cm.caKeyFile, err)
		return err
	}

	keyBlock, _ := pem.Decode(keyData)

	if keyBlock == nil {
		fmt.Printf("Error decoding key file %s %v\n", cm.caKeyFile, err)
		return err
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)

	if err != nil {
		fmt.Printf("Error parsing key file %s %v\n", cm.caKeyFile, err)
		return err
	}

	cm.caPrivateKey = key

	return nil
}

func (cm *certManager) readCertOrCreateAndReadCert() error {
	if !fileExists(cm.caCertFile) {
		fmt.Printf("Cert file %s does not exist, creating\n", cm.caCertFile)

		err := cm.createCertFile()

		if err != nil {
			return err
		}
	}

	certData, err := ioutil.ReadFile(cm.caCertFile)

	if err != nil {
		fmt.Printf("Error reading cert file %s %v\n", cm.caCertFile, err)
		return err
	}

	certBlock, _ := pem.Decode(certData)

	if certBlock == nil {
		fmt.Printf("Error decoding cert file %s %v\n", cm.caCertFile, err)
		return err
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)

	if err != nil {
		fmt.Printf("Error parsing cert file %s %v\n", cm.caCertFile, err)
		return err
	}

	// check if cert's public key matches private key
	caPublicKey := cm.caPrivateKey.Public().(*ecdsa.PublicKey)

	if !caPublicKey.Equal(cm.caPrivateKey.Public()) {
		fmt.Printf("Cert file %s does not match key file %s\n", cm.caCertFile, cm.caKeyFile)

		err := cm.createCertFile()

		if err != nil {
			return err
		}
	}

	//check if cert is expired
	if time.Now().After(cert.NotAfter) {
		fmt.Printf("Cert file %s is expired, creating\n", cm.caCertFile)

		err := cm.createCertFile()

		if err != nil {
			return err
		}
	}

	cm.caCert = cert

	return nil
}

func (cm *certManager) loadCA() error {
	err := cm.readKeyOrCreateAndReadKey()

	if err != nil {
		return err
	}

	err = cm.readCertOrCreateAndReadCert()

	if err != nil {
		return err
	}

	return nil
}

func (cm *certManager) createKeyFile() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		fmt.Printf("Error generating key %v\n", err)
		return err
	}

	keyBlock, err := x509.MarshalECPrivateKey(key)

	if err != nil {
		fmt.Printf("Error marshalling key %v\n", err)
		return err
	}

	keyData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBlock})

	keyFile, err := os.Create(cm.caKeyFile)

	if err != nil {
		fmt.Printf("Error creating key file %v\n", err)
		return err
	}

	defer keyFile.Close()

	_, err = keyFile.Write(keyData)

	if err != nil {
		fmt.Printf("Error writing key file %v\n", err)
		return err
	}

	return nil
}

func (cm *certManager) createCertFile() error {
	err := cm.generateCACertificate()

	if err != nil {
		return err
	}

	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw})

	certFile, err := os.Create(cm.caCertFile)

	if err != nil {
		fmt.Printf("Error creating cert file %v\n", err)
		return err
	}

	defer certFile.Close()

	_, err = certFile.Write(certData)

	if err != nil {
		fmt.Printf("Error writing cert file %v\n", err)
		return err
	}

	return nil
}
func (cm *certManager) generateCACertificate() error {
	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))

	if err != nil {
		return err
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cm.caName,
			Organization: []string{"Local Cert Manager"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(1, 0, 0),

		IsCA:                  true,
		PublicKeyAlgorithm:    x509.ECDSA,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &cm.caPrivateKey.PublicKey, cm.caPrivateKey)

	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(derBytes)

	if err != nil {
		fmt.Printf("Error parsing certificate %v\n", err)
		return err
	}

	cm.caCert = cert

	return nil
}

func (cm *certManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/get-cert" {
		cm.handleGetCert(w, r)
	} else if r.URL.Path == "" || r.URL.Path == "/" {
		w.Write([]byte("Hello World"))
	} else {
		fmt.Printf("Invalid path %s\n", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (cm *certManager) handleGetCert(w http.ResponseWriter, r *http.Request) {
	// get pem encoded certificate request from body if content type is application/pem-certificate-request
	fmt.Printf("Received certificate request\n")

	if r.Method != http.MethodPost {
		fmt.Printf("Invalid method %s\n", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Header.Get("Content-Type") != "application/x-pem-certificate-request" {
		fmt.Printf("Invalid content type %s\n", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	certReqData, err := ioutil.ReadAll(r.Body)

	if err != nil {
		fmt.Printf("Error reading request body %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	certReqBlock, _ := pem.Decode(certReqData)

	if certReqBlock == nil {
		fmt.Printf("Error decoding request body %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	certReq, err := x509.ParseCertificateRequest(certReqBlock.Bytes)

	if err != nil {
		fmt.Printf("Error parsing certificate request %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// generate certificate from certificate request

	tlsCert, err := GenerateTLSCertificate(certReq, cm.caCert, cm.caPrivateKey, cm.certValidDuration)

	if err != nil {
		fmt.Printf("Error generating certificate %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// return pem encoded certificate

	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Raw})

	w.Header().Set("Content-Type", "application/x-pem-file")

	fmt.Printf("Returning certificate\n")

	w.Write(certData)
}

func fileExists(path string) bool {
	if f, err := os.Stat(path); os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatal(err)
	} else if f.IsDir() {
		log.Fatalf("%s is a directory", path)
	}

	return true
}
