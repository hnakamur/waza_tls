package main

import (
	"context"
	"crypto/tls"
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
	if len(os.Args) != 2 {
		usage()
	}

	switch os.Args[1] {
	case "server":
		if err := runServer(); err != nil {
			log.Fatal(err)
		}
	case "client":
		if err := runClient(); err != nil {
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

const port = 8443

// const host = "naruh.dev"
// const certFilename = "naruh.dev.crt"
// const keyFilename = "naruh.dev.key"
// const skipVerifyCert = false

const host = "my-server.example.test"
const certFilename = "../../tests/rsa2048.crt.pem"
const keyFilename = "../../tests/rsa2048.key.pem"
const skipVerifyCert = true

func runServer() error {
	http.HandleFunc("/", HelloServer)
	return http.ListenAndServeTLS(":"+strconv.Itoa(port), certFilename, keyFilename, nil)
}

func runClient() error {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: skipVerifyCert,
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	c := http.Client{Transport: tr}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(port))}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Host = host
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
