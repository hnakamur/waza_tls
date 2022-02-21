package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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

func runServer() error {
	http.HandleFunc("/", HelloServer)
	return http.ListenAndServeTLS(":8443", "naruh.dev.crt", "naruh.dev.key", nil)
}

func runClient() error {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MaxVersion: tls.VersionTLS13}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:8443")
	}
	c := http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodGet, "https://naruh.dev:8443", nil)
	if err != nil {
		return err
	}
	req.Host = "naruh.dev"
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
