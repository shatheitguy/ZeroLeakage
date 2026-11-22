package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnsHandler adapts the engine to miekg/dns for UDP, TCP and DoT.
type dnsHandler struct {
	e     *Engine
	proto string
	zone  string // public hostname, e.g. dns.example.com (for DoT SNI device ids)
}

func (h dnsHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	c := Client{IP: hostOf(w.RemoteAddr()), Proto: h.proto}
	if cs, ok := w.(dns.ConnectionStater); ok {
		if st := cs.ConnectionState(); st != nil {
			c.DeviceID = DeviceFromSNI(st.ServerName, h.zone)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	resp := h.e.Handle(ctx, req, c)
	if h.proto == "udp" {
		size := 512
		if o := req.IsEdns0(); o != nil {
			size = int(o.UDPSize())
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)
}

// DeviceFromSNI extracts "<id>" from "<id>.<zone>" (Android Private DNS hostname).
func DeviceFromSNI(sni, zone string) string {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	if zone == "" || !strings.HasSuffix(sni, "."+zone) {
		return ""
	}
	label := strings.TrimSuffix(sni, "."+zone)
	if strings.Contains(label, ".") {
		return ""
	}
	return label
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

// Servers are the running DNS listeners.
type Servers struct{ list []*dns.Server }

// StartDNS starts plain DNS on addr (UDP+TCP) and DoT on dotAddr when a TLS config is given.
func StartDNS(e *Engine, addr, dotAddr string, tlsConf *tls.Config, zone string, errs chan<- error) *Servers {
	s := &Servers{}
	start := func(srv *dns.Server) {
		s.list = append(s.list, srv)
		go func() {
			if err := srv.ListenAndServe(); err != nil {
				errs <- err
			}
		}()
	}
	if addr != "" {
		start(&dns.Server{Addr: addr, Net: "udp", Handler: dnsHandler{e, "udp", zone}, UDPSize: 65535})
		start(&dns.Server{Addr: addr, Net: "tcp", Handler: dnsHandler{e, "tcp", zone}, ReadTimeout: 10 * time.Second})
	}
	if dotAddr != "" && tlsConf != nil {
		start(&dns.Server{Addr: dotAddr, Net: "tcp-tls", TLSConfig: tlsConf, Handler: dnsHandler{e, "dot", zone}, ReadTimeout: 10 * time.Second})
	}
	return s
}

func (s *Servers) Shutdown() {
	for _, srv := range s.list {
		_ = srv.Shutdown()
	}
}

// DoHHandler serves RFC 8484 DNS-over-HTTPS at /dns-query and /dns-query/<deviceId>.
// trustProxy: take the client IP from X-Forwarded-For / X-Real-IP (when behind a reverse proxy).
func DoHHandler(e *Engine, trustProxy bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(r.URL.Query().Get("dns"), "="))
		case http.MethodPost:
			if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
			wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err != nil || len(wire) < 12 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(wire); err != nil {
			http.Error(w, "bad dns message", http.StatusBadRequest)
			return
		}
		c := Client{IP: ClientIP(r, trustProxy), Proto: "doh"}
		if rest := strings.TrimPrefix(r.URL.Path, "/dns-query"); strings.HasPrefix(rest, "/") {
			c.DeviceID = strings.ToLower(strings.Trim(rest, "/"))
		}
		resp := e.Handle(r.Context(), req, c)
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age=0")
		_, _ = w.Write(out)
	})
}

// ClientIP returns the caller's IP, honouring proxy headers only when told to.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}
