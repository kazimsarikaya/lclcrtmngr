package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/kazimsarikaya/lclcrtmngr/internal/certmanager"
)

type cadomains []string

func (i *cadomains) String() string {
	return strings.Join(*i, ",")
}

func (i *cadomains) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	dataDir           = flag.String("data_dir", "./data", "Data directory")
	caName            = flag.String("ca_name", "Local Certificate Manager", "CA name")
	caDomains         = flag.String("ca_domains", "localhost", "CA domains")
	serverPort        = flag.Int("server_port", 8443, "Server port")
	certValidDuration = flag.Duration("cert_valid_duration", 24*time.Hour, "Certificate valid duration")
)

func init() {
	flag.Parse()
}

func main() {
	caCertFile := filepath.Join(*dataDir, "ca.crt")
	caKeyFile := filepath.Join(*dataDir, "ca.key")

	cadomains := strings.Split(*caDomains, ",")

	fmt.Printf("CA Name: %s\n", *caName)
	fmt.Printf("CA Domains: %s\n", *caDomains)
	fmt.Printf("CA Cert File: %s\n", caCertFile)
	fmt.Printf("CA Key File: %s\n", caKeyFile)
	fmt.Printf("Server Port: %d\n", *serverPort)
	fmt.Printf("Certificate Valid Duration: %s\n", *certValidDuration)

	cm := certmanager.NewCertificateManager(*caName, caCertFile, caKeyFile, cadomains, *certValidDuration)

	err := cm.Start()

	if err != nil {
		log.Fatal(err)
	}

	// Setup TLS listener using GetCertficate for fetching the cert when changes
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *serverPort), &tls.Config{
		GetCertificate: cm.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})

	if err != nil {
		panic(err)
	}

	// Initialize your tls server
	srv := &http.Server{
		Handler:           cm,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx := context.Background()

	// Start goroutine for handling server shutdown.
	go func() {
		<-ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			panic(err)
		}

		cm.Stop()
	}()

	// Serve t
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
