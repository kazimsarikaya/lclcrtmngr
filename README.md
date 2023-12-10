# Local Certificate Manager

This is a simple tool to manage local certificates for development purposes.

The main server app is **lclcrtmngr** inside bin folder. For building just run `make` inside root folder.

## Usage

For certmanager usage just run `lclcrtmngr -h` to see the help.

For web server application just create CertificateWatcher and start it. For details see `example/main.go`.

## Example Go App

An example Go app is inside `example` folder. It uses the `lclcrtmngr` to generate a certificate and key for the server and a certificate for the client. The client certificate is used to authenticate the client to the server. You can just run `bin/examplesrv`.

## Theory of Operation

During TLS handshake, when first message, ClientHelloInfo, arrives at server, the server can choose a valid certificate to send to the client. Hence we can use this to send an ephiremal server certificate which has short life. Also with a timer server can change its certificate periodically.

lclcrtmngr uses this to generate a new certificate and key pair for the server and send it to the server. The server can use this certificate to send to the client. The client can verify the certificate using the CA certificate.

At first run, lclcrtmngr generates a CA certificate and key pair. This is used to sign the server certificate. Just add this CA certificate to your browser or OS trust store, or only for your application's TLS config. For next calls/runs lclcrtmngr uses this CA certificate and key.

For generating server certificate, create ECDSA key and a CertificateRequest with the key. Send this tolclcrtmngr. lclcrtmngr will generate a certificate and send it back. The server can use this certificate as TLS certificate. The client can verify the certificate using the CA certificate. lclcrtmngr's end point is `/get-cert`. For request use `application/x-pem-certificate-request` as content type, response's content type is `application/x-pem-file`. Use SubjectAlternativeNames with domain and ip address during certificate request creation.
