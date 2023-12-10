package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var (
	dataDir    = flag.String("data_dir", "./data", "Data directory")
	caName     = flag.String("ca_name", "local cert manager", "CA name")
	serverPort = flag.Int("server_port", 8443, "Server port")
)

func init() {
	flag.Parse()
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

func generateCACertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(2), big.NewInt(159), nil))

	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   *caName,
			Organization: []string{"Local Cert Manager"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(10, 0, 0),

		IsCA:                  true,
		PublicKeyAlgorithm:    x509.ECDSA,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)

	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)

	if err != nil {
		fmt.Printf("Error parsing certificate %v\n", err)
		return nil, nil, err
	}

	return cert, key, nil
}

func generateTLSCertificateRequest(dnsNames []string) (*x509.CertificateRequest, *ecdsa.PrivateKey, error) {
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

func generateTLSCertificate(certReq *x509.CertificateRequest, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
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
		NotAfter:                now.AddDate(0, 0, 1),
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

func writeCertificateAndKeyToFile(certificatePath string, keyPath string) error {
	cert, key, err := generateCACertificate()

	if err != nil {
		return err
	}

	certData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	keyBlock, err := x509.MarshalECPrivateKey(key)

	if err != nil {
		log.Fatal(err)

	}

	keyData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBlock})

	certFile, err := os.Create(certificatePath)

	if err != nil {
		return err
	}

	defer certFile.Close()

	_, err = certFile.Write(certData)

	if err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)

	if err != nil {
		return err
	}

	defer keyFile.Close()

	_, err = keyFile.Write(keyData)

	if err != nil {
		return err
	}

	return nil
}

func loadCertificate(certificatePath string, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certData, err := ioutil.ReadFile(certificatePath)

	if err != nil {
		return nil, nil, err
	}

	certBlock, _ := pem.Decode(certData)

	cert, err := x509.ParseCertificate(certBlock.Bytes)

	if err != nil {
		fmt.Printf("Error parsing certificate file %s %v\n", certificatePath, err)
		return nil, nil, err
	}

	keyData, err := ioutil.ReadFile(keyPath)

	if err != nil {
		return nil, nil, err
	}

	keyBlock, _ := pem.Decode(keyData)

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)

	if err != nil {
		fmt.Printf("Error parsing key file %s %v\n", keyPath, err)
		return nil, nil, err
	}

	return cert, key, nil
}

func main() {
	caCertFile := filepath.Join(*dataDir, "ca.crt")
	caKeyFile := filepath.Join(*dataDir, "ca.key")

	var err error
	var caCert *x509.Certificate
	var caKey *ecdsa.PrivateKey

	if fileExists(caCertFile) && fileExists(caKeyFile) {
		fmt.Println("CA certificate and key already exist")

		caCert, caKey, err = loadCertificate(caCertFile, caKeyFile)

		if err != nil {
			log.Fatal(err)
		}

	} else {
		fmt.Println("Generating CA certificate and key")
		err = writeCertificateAndKeyToFile(caCertFile, caKeyFile)

		if err != nil {
			log.Fatal(err)
		}

		caCert, caKey, err = loadCertificate(caCertFile, caKeyFile)

		if err != nil {
			log.Fatal(err)
		}
	}

	tlsCertReq, tlsKey, err := generateTLSCertificateRequest([]string{
		"localhost",
	})

	if err != nil {
		log.Fatal(err)
	}

	tlsCert, err := generateTLSCertificate(tlsCertReq, caCert, caKey)

	if err != nil {
		log.Fatal(err)
	}

	//create tls server with gorilla mux

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{tlsCert.Raw},
				PrivateKey:  tlsKey,
			},
		},
	}

	httpServer := http.Server{
		Addr:      fmt.Sprintf(":%d", *serverPort),
		TLSConfig: &tlsConfig,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", r.URL.Path)
	})

	fmt.Printf("Starting server on port %d\n", *serverPort)

	if err := httpServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}

}
