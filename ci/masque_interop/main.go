// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// A one-transaction, loopback-only fixture for quic-go/masque-go interop.
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const targetName = "h3-origin.invalid"

func main() {
	port := flag.Int("origin-port", 0, "fixed loopback origin port")
	certPath := flag.String("cert", "", "ephemeral fixture cert PEM")
	keyPath := flag.String("key", "", "ephemeral fixture key PEM")
	flag.Parse()
	if *port < 1 || *port > 65535 || flag.NArg() != 0 {
		log.Fatal("the fixture needs one exact loopback origin port")
	}
	auth := os.Getenv("RUYIHTTP_FIXTURE_RELAY_AUTH")
	if auth == "" {
		log.Fatal("fixture authentication is mandatory")
	}
	leaf, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatal(err)
	}
	loop := net.IPv4(127, 0, 0, 1)
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	// The handler receives a preconnected socket, never a dial function or a
	// destination parsed from requests. It can only forward to this endpoint.
	fixed := &net.UDPAddr{IP: loop, Port: *port}
	egress, err := net.DialUDP("udp4", &net.UDPAddr{IP: loop}, fixed)
	if err != nil {
		log.Fatal(err)
	}
	defer egress.Close()
	authority := listener.LocalAddr().String()
	exactTarget := net.JoinHostPort(targetName, strconv.Itoa(*port))
	exactPath := fmt.Sprintf("/.well-known/masque/udp/%s/%d/", targetName, *port)
	template, err := uritemplate.New("https://" + authority + "/.well-known/masque/udp/{target_host}/{target_port}/")
	if err != nil {
		log.Fatal(err)
	}
	var proxy masque.Proxy
	var used atomic.Bool
	var outMu sync.Mutex
	writeEvent := func(fields map[string]any) {
		outMu.Lock()
		defer outMu.Unlock()
		if err := json.NewEncoder(os.Stdout).Encode(fields); err != nil {
			log.Print(err)
		}
	}
	server := &http3.Server{
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{leaf}}),
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1400},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, err := masque.ParseProxyRequest(r, template)
			if err != nil || req.Target != exactTarget || r.URL.RequestURI() != exactPath {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			values := r.Header.Values("Proxy-Authorization")
			if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(auth)) != 1 || r.Header.Get("Authorization") != "" {
				w.Header().Set("Proxy-Authenticate", `Basic realm="test-only"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			if !used.CompareAndSwap(false, true) {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			writeEvent(map[string]any{"accepted_connect_udp": r.URL.RequestURI(), "alpn": r.TLS.NegotiatedProtocol, "proxy_auth_matched": true})
			if err := proxy.ProxyConnectedSocket(w, req, egress); err != nil {
				log.Print(err)
			}
			writeEvent(map[string]any{"tunnel_retired": true})
		}),
	}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("missing Go module build info")
	}
	versions := map[string]string{}
	for _, dep := range build.Deps {
		if dep.Path == "github.com/quic-go/masque-go" || dep.Path == "github.com/quic-go/quic-go" {
			if dep.Replace != nil {
				log.Fatal("unexpected Go module replacement")
			}
			versions[dep.Path] = dep.Version
		}
	}
	writeEvent(map[string]any{"relay_port": listener.LocalAddr().(*net.UDPAddr).Port,
		"egress_port": egress.LocalAddr().(*net.UDPAddr).Port, "modules": versions, "go": build.GoVersion})
	go func() {
		io.Copy(io.Discard, os.Stdin) // EOF from the Python harness ends the test.
		server.Close()
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
	proxy.Close()
}
