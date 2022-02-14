package main

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
)

func TestTLSConn(t *testing.T) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MaxVersion: tls.VersionTLS12}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:8443")
	}
	c := http.Client{Transport: tr}
	req, err := http.NewRequest(http.MethodGet, "https://naruh.dev:8443", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "naruh.dev"
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("status=%d", resp.StatusCode)
}
