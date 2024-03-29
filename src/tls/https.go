package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	http.HandleFunc("/", HelloServer)
	return http.ListenAndServeTLS(":"+strconv.Itoa(*port), *certFilename, *keyFilename, nil)
}

func runClient(args []string) error {
	var fs = flag.NewFlagSet("client", flag.ExitOnError)
	host := fs.String("host", defaultHost, "host")
	port := fs.Int("port", defaultPort, "port")
	maxMinorVersion := fs.Int("max-minor-version", 3, "TLS max version 3=1.3, 2=1.2")
	skipVerifyCert := fs.Bool("skip-verify-cert", defaultSkipVerifyCert, "skip verify certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var maxVersion uint16
	switch *maxMinorVersion {
	case 2:
		maxVersion = tls.VersionTLS12
	case 3:
		maxVersion = tls.VersionTLS13
	default:
		return fmt.Errorf("invalid max minor version: %d", *maxMinorVersion)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MaxVersion:         maxVersion,
		InsecureSkipVerify: *skipVerifyCert,
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	}
	c := http.Client{Transport: tr}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(*host, strconv.Itoa(*port))}
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
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s (client|server)\n", os.Args[0])
	os.Exit(2)
}
