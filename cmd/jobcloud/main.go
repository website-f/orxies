// Command jobcloud is the single-binary entrypoint.
//
// Usage:
//
//	jobcloud serve --data /etc/jobcloud --sites /etc/jobcloud/sites
//	jobcloud hash 'plaintext-password'   # generate bcrypt for config.yml
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"jobcloud/internal/acme"
	"jobcloud/internal/audit"
	"jobcloud/internal/auth"
	"jobcloud/internal/config"
	"jobcloud/internal/metrics"
	"jobcloud/internal/proxy"
	"jobcloud/internal/security"
	"jobcloud/internal/server"
	"jobcloud/internal/ui"
)

// Version is set via -ldflags "-X main.Version=..." at build time.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "hash":
		cmdHash(os.Args[2:])
	case "totp":
		cmdTOTP(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("jobcloud", Version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

const usage = `jobcloud — reverse proxy + admin UI for multi-project hosting

Commands:
  serve       Run the proxy + admin UI
  hash PW     Print a bcrypt hash for the given password (for config.yml)
  totp [USER] Generate a TOTP 2FA secret + otpauth URI (for config.yml)
  version     Print the build version

Flags for 'serve':
  --data DIR     Data directory (default /etc/jobcloud)
  --sites DIR    Sites config dir (default <data>/sites)
  --certs DIR    ACME cert storage (default <data>/certs)
`

func cmdHash(args []string) {
	if len(args) != 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, "usage: jobcloud hash <plaintext-password>")
		os.Exit(2)
	}
	h, err := auth.HashPassword(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash:", err)
		os.Exit(1)
	}
	fmt.Println(h)
}

func cmdTOTP(args []string) {
	account := "admin"
	if len(args) >= 1 && args[0] != "" {
		account = args[0]
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		fatal("totp: %v", err)
	}
	fmt.Println("Add this to the admin in config.yml:")
	fmt.Println()
	fmt.Printf("  totp_secret: \"%s\"\n", secret)
	fmt.Println()
	fmt.Println("Then import into your authenticator app via this otpauth URI")
	fmt.Println("(or render it as a QR code):")
	fmt.Println()
	fmt.Println("  " + auth.TOTPURI("jobcloud", account, secret))
	fmt.Println()
	fmt.Println("After restarting jobcloud, that admin will be prompted for a code at login.")
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data", "/etc/jobcloud", "data directory")
	sitesDir := fs.String("sites", "", "sites directory (default <data>/sites)")
	certsDir := fs.String("certs", "", "ACME cert storage (default <data>/certs)")
	wwwDir := fs.String("www", "", "static-sites base dir (default <data>/www)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	_ = fs.Parse(args)

	configureLogging(*logLevel)
	slog.Info("jobcloud starting", "version", Version, "data", *dataDir)

	if *sitesDir == "" {
		*sitesDir = filepath.Join(*dataDir, "sites")
	}
	if *certsDir == "" {
		*certsDir = filepath.Join(*dataDir, "certs")
	}
	if *wwwDir == "" {
		*wwwDir = filepath.Join(*dataDir, "www")
	}
	for _, d := range []string{*dataDir, *sitesDir, *certsDir, *wwwDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			fatal("mkdir %s: %v", d, err)
		}
	}

	g, err := config.LoadGlobal(*dataDir)
	if err != nil {
		fatal("load global config: %v", err)
	}

	adminAllow, err := security.ParseCIDRs(g.AdminAllowCIDRs)
	if err != nil {
		fatal("admin_allow_cidrs: %v", err)
	}
	if len(adminAllow) > 0 {
		slog.Info("admin UI IP allowlist active", "cidrs", g.AdminAllowCIDRs)
	}

	auditLog, err := audit.Open(filepath.Join(*dataDir, "audit.log"))
	if err != nil {
		slog.Warn("audit log unavailable — mirroring to stdout only", "err", err)
	}

	authMgr, err := auth.New(g, *dataDir)
	if err != nil {
		fatal("auth: %v", err)
	}
	loginThrottle := auth.NewThrottle()

	acmeMgr, err := acme.New(*certsDir, g.ACMEEmail, g.ACMEDirectory)
	if err != nil {
		fatal("acme: %v", err)
	}

	store := config.NewStore()
	registry := metrics.NewRegistry()
	router := proxy.NewRouter(store, registry, g.TrustForwardedHeaders, *wwwDir)

	uiSrv, err := ui.New(&ui.Server{
		Store:         store,
		Metrics:       registry,
		Auth:          authMgr,
		ACME:          acmeMgr,
		SitesDir:      *sitesDir,
		Version:       Version,
		StartAt:       time.Now(),
		Audit:         auditLog,
		LoginThrottle: loginThrottle,
	})
	if err != nil {
		fatal("ui: %v", err)
	}

	// Build the watcher last so we can wire OnReload to refresh the
	// router, ACME, and metrics registry whenever the on-disk config
	// changes.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := &config.Watcher{
		SitesDir: *sitesDir,
		Store:    store,
		OnReload: func(sites []*config.Site, errs []error) {
			router.Reload(sites)
			// Sync certmagic with the current domain list.
			acmeMgr.SyncDomains(ctx, acme.DomainsFromSites(sites))
			// Prune metrics for sites that vanished.
			keep := map[string]bool{}
			for _, s := range sites {
				if s.Enabled {
					for _, d := range s.AllDomains() {
						keep[d] = true
					}
					keep[s.Domain] = true
				}
			}
			registry.Prune(keep)
		},
	}
	uiSrv.ReloadCallback = func(_ context.Context) {
		// Force a synchronous reload after a UI edit so the next page
		// view reflects the change. Reuses the watcher's reload path.
		sites, _ := config.LoadSites(*sitesDir)
		store.Replace(sites)
		watcher.OnReload(sites, nil)
	}

	// Start the watcher (does the initial load + ongoing fsnotify).
	go func() {
		if err := watcher.Run(ctx); err != nil {
			slog.Error("watcher exited", "err", err)
		}
	}()

	// Wait for the watcher's initial load to complete before starting
	// listeners — small race but tiny.
	time.Sleep(50 * time.Millisecond)

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		slog.Info("got signal", "signal", s)
		cancel()
	}()

	deps := &server.Deps{
		Global:           g,
		Store:            store,
		Watcher:          watcher,
		Router:           router,
		UI:               uiSrv,
		Auth:             authMgr,
		ACME:             acmeMgr,
		Registry:         registry,
		StartedAt:        time.Now(),
		AdminAllow:       adminAllow,
		AdminForceSecure: g.AdminForceSecureCookie,
	}
	if err := server.Run(ctx, deps); err != nil {
		fatal("server: %v", err)
	}
	slog.Info("jobcloud shutdown complete")
}

func configureLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "jobcloud: "+format+"\n", args...)
	os.Exit(1)
}
