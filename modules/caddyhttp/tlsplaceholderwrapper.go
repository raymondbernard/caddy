// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// tlsPlaceholderWrapper is a no-op listener wrapper that marks
// where the TLS listener should be in a chain of listener wrappers.
// It should only be used if another listener wrapper must be placed
// in front of the TLS handshake.
type tlsPlaceholderWrapper struct {
	net.Listener `json:"listener,omitempty"`
}

func (tlsPlaceholderWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.tls",
		New: func() caddy.Module { return new(tlsPlaceholderWrapper) },
	}
}

func (tlsPlaceholderWrapper) WrapListener(ln net.Listener) net.Listener {
	return &tlsPlaceholderWrapper{Listener: ln}
}

func (tlsPlaceholderWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (l *tlsPlaceholderWrapper) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &tlsPlaceholderConn{
		Conn: c,
		r:    bufio.NewReader(c),
	}, nil
}

type tlsPlaceholderConn struct {
	net.Conn
	once sync.Once
	r    *bufio.Reader
}

// Read tries to peek at the first few bytes of the request, and if we get
// an error reading the headers, and that error was due to the bytes looking
// like an HTTP request, then we perform a HTTP->HTTPS redirect on the same
// port as the original connection.
func (c *tlsPlaceholderConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		_, err := c.r.Peek(1)
		if err != nil {
			if re, ok := err.(tls.RecordHeaderError); ok && re.Conn != nil && tlsRecordHeaderLooksLikeHTTP(re.RecordHeader) {
				// TODO: Actually do the redirect correctly, by matching
				// the hostname and port of the original connection.
				_, err := io.WriteString(re.Conn, "HTTP/1.0 308 Permanent Redirect\r\nLocation: https://localhost:8881\r\n\r\n")
				if err != nil {
					// TODO
					fmt.Printf("Couldn't write HTTP->HTTPS redirect.\n")
				}
				re.Conn.Close()
			}
		}
	})
	return c.r.Read(p)
}

// tlsRecordHeaderLooksLikeHTTP reports whether a TLS record header
// looks like it might've been a misdirected plaintext HTTP request.
func tlsRecordHeaderLooksLikeHTTP(hdr [5]byte) bool {
	switch string(hdr[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

// Interface guard
var _ caddy.ListenerWrapper = (*tlsPlaceholderWrapper)(nil)
var _ caddyfile.Unmarshaler = (*tlsPlaceholderWrapper)(nil)
