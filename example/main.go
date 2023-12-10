package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"time"

	"github.com/kazimsarikaya/lclcrtmngr/pkg/certwatcher"
)

var (
	certManagerUrl *string
	caFile         *string
)

func init() {
	certManagerUrl = flag.String("cert-manager-url", "https://localhost:8443/get-cert", "The URL of the cert-manager service")
	caFile = flag.String("ca-path", "./data/ca.crt", "The path to the CA certificate")
}

func main() {
	cw := certwatcher.NewCertificateWatcher(*certManagerUrl, *caFile, []string{"localhost"})

	err := cw.Start()

	if err != nil {
		panic(err)
	}

	// Setup TLS listener using GetCertficate for fetching the cert when changes
	listener, err := tls.Listen("tcp", "localhost:9443", &tls.Config{
		GetCertificate: cw.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})

	if err != nil {
		panic(err)
	}

	// Initialize your tls server
	srv := &http.Server{
		Handler:           &sampleServer{},
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

		cw.Stop()
	}()

	// Serve t
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}

type sampleServer struct{}

func (s *sampleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello World"))
}
