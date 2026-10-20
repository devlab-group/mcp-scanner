// Command mcp-scanner-api serves scans and health checks over HTTP
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/api"
	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"

	"github.com/devlab-group/mcp-scanner/internal/app"
)

// defaultTokenEnv names the bearer-token environment variable used when none is configured
const defaultTokenEnv = "MCP_SCANNER_API_TOKEN"

// defaultAddr keeps an unauthenticated default deployment on loopback. Binding elsewhere must be
// an explicit operator decision.
const defaultAddr = "127.0.0.1:8080"

// Explicit timeouts bound every connection phase instead of relying on net/http's zero-value
// fallbacks between ReadTimeout, ReadHeaderTimeout, and IdleTimeout.
const (
	// apiReadHeaderTimeout limits receipt of the request line and headers
	apiReadHeaderTimeout = 10 * time.Second
	// apiReadTimeout complements the body-size limit with a time limit
	apiReadTimeout = 30 * time.Second
	// apiWriteTimeout allows large results while bounding stalled readers
	apiWriteTimeout = 2 * time.Minute
	// apiIdleTimeout supports polling without keeping idle connections forever
	apiIdleTimeout = 2 * time.Minute
	// apiMaxHeaderBytes states net/http's default explicitly
	apiMaxHeaderBytes = 1 << 20
)

// knownTargetKinds lists API-supported targets. Config targets expand into
// multiple scans and do not fit the API's one-target contract.
var knownTargetKinds = map[model.TargetKind]bool{
	model.TargetRemote:  true,
	model.TargetStdio:   true,
	model.TargetStatic:  true,
	model.TargetSource:  true,
	model.TargetPackage: true,
}

func main() {
	addr := envOr("MCP_SCANNER_API_ADDR", defaultAddr)
	configPath := os.Getenv("MCP_SCANNER_API_CONFIG")

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Share preparation and base options with the CLI. Requests may override
	// analyzers, fail_on, and blocking severity; active probes remain deployment policy.
	sc := scanner.New(analyzer.Default, app.NewPreparer(cfg), logger)

	opts, err := apiOptions(cfg, logger)
	if err != nil {
		log.Fatalf("%v", err)
	}
	srv, err := api.NewServer(sc, opts)
	if err != nil {
		// Refuse to start when sensitive target kinds lack required safeguards
		log.Fatalf("configure api server: %v", err)
	}

	httpSrv := newHTTPServer(addr, srv.Handler())

	go func() {
		logger.Info("mcp-scanner-api listening", "addr", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	logger.Info("shutting down")
	srv.Shutdown(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
}

// apiOptions centralizes production option construction so tests exercise the same path
func apiOptions(cfg config.Config, logger *slog.Logger) (api.Options, error) {
	sopts, err := app.ScanOptions(cfg)
	if err != nil {
		return api.Options{}, fmt.Errorf("build scan options: %w", err)
	}

	pol := policy.Default()
	if cfg.FailOn != "" {
		// Reject invalid policy at startup and use the same parsing as the CLI
		sev, err := policy.ParseFailOn(cfg.FailOn)
		if err != nil {
			return api.Options{}, fmt.Errorf("fail_on: %w", err)
		}
		pol.FailOn = sev
	}
	// Incomplete scans fail by default, as they do in the CLI
	if cfg.TolerateUnknown {
		pol.FailOnUnknown = false
	}
	pol.Baseline = cfg.Baseline

	kinds, err := allowedTargetKinds()
	if err != nil {
		return api.Options{}, err
	}
	return api.Options{
		Policy:             pol,
		ScanOptions:        sopts,
		AllowedTargetKinds: kinds,
		TokenEnv:           envOr("MCP_SCANNER_API_TOKEN_ENV", defaultTokenEnv),
		BaseDir:            os.Getenv("MCP_SCANNER_API_BASE_DIR"),
		// Log details hidden from redacted API responses
		Logger: logger,
	}, nil
}

// newHTTPServer builds the production listener with explicit resource limits
func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: apiReadHeaderTimeout,
		ReadTimeout:       apiReadTimeout,
		WriteTimeout:      apiWriteTimeout,
		IdleTimeout:       apiIdleTimeout,
		MaxHeaderBytes:    apiMaxHeaderBytes,
	}
}

// allowedTargetKinds parses MCP_SCANNER_API_ALLOWED_KINDS. Empty uses the API
// default; unknown kinds stop startup.
func allowedTargetKinds() ([]model.TargetKind, error) {
	raw := os.Getenv("MCP_SCANNER_API_ALLOWED_KINDS")
	if raw == "" {
		return nil, nil
	}
	var out []model.TargetKind
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kind := model.TargetKind(part)
		if !knownTargetKinds[kind] {
			return nil, fmt.Errorf("MCP_SCANNER_API_ALLOWED_KINDS: unknown target kind %q", part)
		}
		out = append(out, kind)
	}
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
