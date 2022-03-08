package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "server":
		if err := runServer(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "client":
		if err := runClient(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()

	}
}

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
}

const defaultPort = 8443
const defaultHost = "my-server.example.test"
const defaultCertFilename = "../../tests/rsa2048.crt.pem"
const defaultKeyFilename = "../../tests/rsa2048.key.pem"
const defaultSkipVerifyCert = true

func runServer(args []string) error {
	var fs = flag.NewFlagSet("server", flag.ExitOnError)
	certFilename := fs.String("cert", defaultCertFilename, "certificate filename")
	keyFilename := fs.String("key", defaultKeyFilename, "key filename")
	port := fs.Int("port", defaultPort, "port")
	clientAuth := tls.NoClientCert
	fs.Var(&ClientAuthValue{ClientAuth: &clientAuth}, "client-auth", "TLS client authentication")
	clientCAFile := fs.String("client-ca", "", "client certificate authority filename")
	if err := fs.Parse(args); err != nil {
		return err
	}

	http.HandleFunc("/", HelloServer)
	tlsConfig := &tls.Config{
		ClientAuth: clientAuth,
	}
	if *clientCAFile != "" {
		caCert, err := ioutil.ReadFile(*clientCAFile)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.ClientCAs = caCertPool
	}
	s := http.Server{
		Addr:      ":" + strconv.Itoa(*port),
		TLSConfig: tlsConfig,
	}
	return s.ListenAndServeTLS(*certFilename, *keyFilename)
}

type ClientAuthValue struct {
	ClientAuth *tls.ClientAuthType
}

func (v ClientAuthValue) String() string {
	if v.ClientAuth != nil {
		return clientAuthTypeToString(*v.ClientAuth)
	}
	return ""
}

func (v ClientAuthValue) Set(s string) error {
	if t, err := parseClientAuthTypeString(s); err != nil {
		return err
	} else {
		*v.ClientAuth = t
	}
	return nil
}

func parseClientAuthTypeString(s string) (tls.ClientAuthType, error) {
	switch s {
	case "NoClientCert":
		return tls.NoClientCert, nil
	case "RequestClientCert":
		return tls.RequestClientCert, nil
	case "RequireAnyClientCert":
		return tls.RequireAnyClientCert, nil
	case "VerifyClientCertIfGiven":
		return tls.VerifyClientCertIfGiven, nil
	case "RequireAndVerifyClientCert":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return tls.NoClientCert, errors.New("invalid ClientAuthType value")
	}
}

func clientAuthTypeToString(ca tls.ClientAuthType) string {
	switch ca {
	case tls.NoClientCert:
		return "NoClientCert"
	case tls.RequestClientCert:
		return "RequestClientCert"
	case tls.RequireAnyClientCert:
		return "RequireAnyClientCert"
	case tls.VerifyClientCertIfGiven:
		return "VerifyClientCertIfGiven"
	case tls.RequireAndVerifyClientCert:
		return "RequireAndVerifyClientCert"
	default:
		return ""
	}
}

func runClient(args []string) error {
	var fs = flag.NewFlagSet("client", flag.ExitOnError)
	host := fs.String("host", defaultHost, "host")
	port := fs.Int("port", defaultPort, "port")
	skipVerifyCert := fs.Bool("skip-verify-cert", defaultSkipVerifyCert, "skip verify certificate")
	certFilename := fs.String("cert", "", "client certificate filename")
	keyFilename := fs.String("key", "", "client key filename")
	caFilename := fs.String("ca", "", "certificate authority filename")
	reqCount := fs.Int("req-count", 1, "request count")
	clientSessionCacheCapacity := fs.Int("client-session-cache-capacity", 0, "client session cache capacity (0=disabled)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: *skipVerifyCert,
	}
	if *certFilename != "" && *keyFilename != "" {
		cert, err := tls.LoadX509KeyPair(*certFilename, *keyFilename)
		if err != nil {
			return err
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}
	if *caFilename != "" {
		caCert, err := ioutil.ReadFile(*caFilename)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}
	if *clientSessionCacheCapacity > 0 {
		tr.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(*clientSessionCacheCapacity)
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	}

	c := http.Client{Transport: tr}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(*host, strconv.Itoa(*port))}
	for i := 0; i < *reqCount; i++ {
		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		req.Host = *host
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return err
		}

		log.Printf("status=%d", resp.StatusCode)
		c.CloseIdleConnections()
	}
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s (client|server)\n", os.Args[0])
	os.Exit(2)
}
