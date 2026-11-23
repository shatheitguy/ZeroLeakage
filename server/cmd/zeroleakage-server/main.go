// Command zeroleakage-server is the ZeroLeakage network DNS filter and (optional) account/sync server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/api"
	"github.com/shatheitguy/ZeroLeakage/server/internal/clients"
	"github.com/shatheitguy/ZeroLeakage/server/internal/dnsserver"
	"github.com/shatheitguy/ZeroLeakage/server/internal/guard"
	"github.com/shatheitguy/ZeroLeakage/server/internal/lists"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
	"github.com/shatheitguy/ZeroLeakage/server/internal/upstream"
)

// version is set at build time: -ldflags "-X main.version=1.0.0"
var version = "dev"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	dataDir := flag.String("data", env("ZL_DATA", "./data"), "data directory (database, lists, TLS cert)")
	dnsAddr := flag.String("dns", env("ZL_DNS_ADDR", ":53"), "plain DNS listen address (UDP+TCP); empty to disable")
	httpAddr := flag.String("http", env("ZL_HTTP_ADDR", ":3080"), "dashboard, API and DoH over plain HTTP (put behind a TLS reverse proxy)")
	httpsAddr := flag.String("https", env("ZL_HTTPS_ADDR", ":443"), "dashboard, API and DoH over HTTPS (needs a cert)")
	dotAddr := flag.String("dot", env("ZL_DOT_ADDR", ":853"), "DNS-over-TLS listen address (needs a cert)")
	certFile := flag.String("cert", env("ZL_TLS_CERT", ""), "TLS certificate (default <data>/tls.crt)")
	keyFile := flag.String("key", env("ZL_TLS_KEY", ""), "TLS key (default <data>/tls.key)")
	trustProxy := flag.Bool("trust-proxy", env("ZL_TRUST_PROXY", "false") == "true", "use X-Forwarded-For for client IPs (only behind your own proxy)")
	debug := flag.Bool("debug", env("ZL_DEBUG", "false") == "true", "verbose logging")
	showVersion := flag.Bool("version", false, "print version and exit")
	health := flag.Bool("healthcheck", false, "check that the running server answers on -http and exit (for Docker HEALTHCHECK)")
	flag.Parse()
	if *showVersion {
		fmt.Println("zeroleakage-server", version)
		return
	}
	if *health {
		os.Exit(healthcheck(*httpAddr))
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if err := run(log, config{*dataDir, *dnsAddr, *httpAddr, *httpsAddr, *dotAddr, *certFile, *keyFile, *trustProxy}); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

type config struct {
	dataDir, dnsAddr, httpAddr, httpsAddr, dotAddr, cert, key string
	trustProxy                                                bool
}

func run(log *slog.Logger, c config) error {
	if err := os.MkdirAll(c.dataDir, 0o750); err != nil {
		return err
	}
	st, err := store.Open(c.dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	settings, err := st.GetSettings(store.DefaultSettings(lists.DefaultEnabled()))
	if err != nil {
		return err
	}
	lm := lists.NewManager(c.dataDir, log)
	up := upstream.New(upstream.Resolver{}, nil, nil)
	api.ConfigureUpstream(up, settings)

	engine := dnsserver.NewEngine(lm, up, st, log)
	g := guard.New(st, c.dataDir, log)
	if err := g.Load(); err != nil {
		return err
	}
	engine.Guard = g
	tracker := clients.NewTracker(st, log, func() string { return engine.Settings().LocalPTRResolver })
	engine.Clients = tracker
	if err := engine.Reload(settings); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Built-in lists load instantly; remote lists and Guard feeds download in the background (daily).
	listIDs := engine.ListIDs()
	go lm.Rebuild(ctx, listIDs, 24*time.Hour)
	go g.RefreshFeeds(ctx, 24*time.Hour)
	go g.Run(ctx)
	go tracker.Run(ctx)
	go engine.RunBackground(ctx)

	tlsConf := loadTLS(c, log)
	errs := make(chan error, 8)
	dnsServers := dnsserver.StartDNS(engine, c.dnsAddr, c.dotAddr, tlsConf, settings.PublicHostname, errs)
	defer dnsServers.Shutdown()

	a := &api.API{Engine: engine, Store: st, Lists: lm, Upstream: up, Guard: g, Clients: tracker, Log: log, Version: version, TrustProxy: c.trustProxy}
	a.MarkBuilt(listIDs)
	handler := a.Handler()
	var httpServers []*http.Server
	serve := func(addr string, tc *tls.Config) {
		srv := &http.Server{Addr: addr, Handler: handler, TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
		httpServers = append(httpServers, srv)
		go func() {
			var err error
			if tc != nil {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- fmt.Errorf("%s: %w", addr, err)
			}
		}()
	}
	if c.httpAddr != "" {
		serve(c.httpAddr, nil)
	}
	if c.httpsAddr != "" && tlsConf != nil {
		serve(c.httpsAddr, tlsConf)
	}

	log.Info("ZeroLeakage server running", "version", version, "dns", c.dnsAddr, "http", c.httpAddr,
		"https", ifTLS(tlsConf, c.httpsAddr), "dot", ifTLS(tlsConf, c.dotAddr), "data", c.dataDir)
	if n, _ := st.UserCount(); n == 0 {
		dash := c.httpAddr
		if strings.HasPrefix(dash, ":") {
			dash = "<this-server-ip>" + dash
		}
		log.Info("first run: open the dashboard to create the admin account", "url", "http://"+dash)
	}

	select {
	case <-ctx.Done():
	case err := <-errs:
		log.Error("listener failed", "err", err)
		stop()
		defer func() { os.Exit(1) }()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range httpServers {
		_ = s.Shutdown(shutdownCtx)
	}
	log.Info("stopped")
	return nil
}

func ifTLS(tc *tls.Config, addr string) string {
	if tc == nil || addr == "" {
		return "off (no certificate)"
	}
	return addr
}

// loadTLS reads <data>/tls.crt + tls.key (or the given paths) and reloads them when they change on disk,
// so certificates renewed by a reverse proxy or certbot are picked up without a restart.
func loadTLS(c config, log *slog.Logger) *tls.Config {
	cert, key := c.cert, c.key
	if cert == "" {
		cert = filepath.Join(c.dataDir, "tls.crt")
	}
	if key == "" {
		key = filepath.Join(c.dataDir, "tls.key")
	}
	if _, err := os.Stat(cert); err != nil {
		return nil
	}
	var (
		loaded  *tls.Certificate
		modTime time.Time
	)
	get := func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		fi, err := os.Stat(cert)
		if err == nil && (loaded == nil || fi.ModTime().After(modTime)) {
			kp, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				if loaded == nil {
					return nil, err
				}
				log.Warn("TLS reload failed, keeping old certificate", "err", err)
			} else {
				loaded, modTime = &kp, fi.ModTime()
			}
		}
		return loaded, nil
	}
	if _, err := get(nil); err != nil {
		log.Warn("TLS certificate unusable; DoT/HTTPS disabled", "err", strings.TrimSpace(err.Error()))
		return nil
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: get, NextProtos: []string{"h2", "http/1.1", "dot"}}
}

// healthcheck GETs /api/v1/status on the local HTTP listener; exit code 0 when healthy.
func healthcheck(addr string) int {
	host := addr
	if strings.HasPrefix(host, ":") || strings.HasPrefix(host, "0.0.0.0:") {
		host = "127.0.0.1:" + host[strings.LastIndex(host, ":")+1:]
	}
	cl := &http.Client{Timeout: 4 * time.Second}
	resp, err := cl.Get("http://" + host + "/api/v1/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: HTTP", resp.StatusCode)
		return 1
	}
	return 0
}
