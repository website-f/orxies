// Command orxies is the single-binary entrypoint.
//
// Usage:
//
//	orxies serve --data /etc/orxies --sites /etc/orxies/sites
//	orxies hash 'plaintext-password'   # generate bcrypt for config.yml
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"orxies/internal/acme"
	"orxies/internal/agent"
	"orxies/internal/audit"
	"orxies/internal/auth"
	"orxies/internal/config"
	"orxies/internal/deploy"
	"orxies/internal/metrics"
	"orxies/internal/proxy"
	"orxies/internal/secretbox"
	"orxies/internal/security"
	"orxies/internal/server"
	pstore "orxies/internal/store"
	"orxies/internal/ui"
	"orxies/internal/webhook"
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
	case "agent":
		cmdAgent(os.Args[2:])
	case "check-sites":
		cmdCheckSites(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("orxies", Version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

const usage = `orxies — reverse proxy + admin UI for multi-project hosting

Commands:
  serve        Run the proxy + admin UI + deploy control plane
  agent        Run the privileged orchestration agent (Docker access)
  hash PW      Print a bcrypt hash for the given password (for config.yml)
  totp [USER]  Generate a TOTP 2FA secret + otpauth URI (for config.yml)
  check-sites  Validate sites/*.yml against current rules (upgrade preflight)
  version      Print the build version

Flags for 'serve':
  --data DIR          Data directory (default /etc/orxies)
  --sites DIR         Sites config dir (default <data>/sites)
  --certs DIR         ACME cert storage (default <data>/certs)
  --www DIR           Static-sites base dir (default <data>/www)
  --agent-socket PATH orxies-agent socket (default /run/orxies/agent.sock)

Flags for 'agent':
  --socket PATH  Unix socket to listen on (default /run/orxies/agent.sock)
  --data DIR     Data dir holding agent.key (default /etc/orxies)
`

func cmdHash(args []string) {
	if len(args) != 1 || args[0] == "" {
		fmt.Fprintln(os.Stderr, "usage: orxies hash <plaintext-password>")
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
	fmt.Println("  " + auth.TOTPURI("orxies", account, secret))
	fmt.Println()
	fmt.Println("After restarting orxies, that admin will be prompted for a code at login.")
}

// cmdCheckSites validates the site config files against the SAME rules
// the server uses at load time — a safe preflight before upgrading, so
// you can see which (if any) existing sites the new version would reject
// (and therefore not route). Exits non-zero if any site is rejected.
func cmdCheckSites(args []string) {
	fs := flag.NewFlagSet("check-sites", flag.ExitOnError)
	dataDir := fs.String("data", "/etc/orxies", "data directory")
	sitesDir := fs.String("sites", "", "sites directory (default <data>/sites)")
	_ = fs.Parse(args)
	if *sitesDir == "" {
		*sitesDir = filepath.Join(*dataDir, "sites")
	}

	sites, errs := config.LoadSites(*sitesDir)
	fmt.Printf("Checking %s\n\n", *sitesDir)
	for _, s := range sites {
		state := "enabled"
		if !s.Enabled {
			state = "disabled"
		}
		fmt.Printf("  OK    %-40s (%s, %s)\n", s.Domain, s.Filename, state)
	}
	for _, e := range errs {
		fmt.Printf("  FAIL  %v\n", e)
	}

	total := len(sites) + len(errs)
	fmt.Printf("\n%d site file(s): %d OK, %d rejected\n", total, len(sites), len(errs))
	if len(errs) > 0 {
		fmt.Println()
		fmt.Println("Rejected files will NOT be routed by the new version — the rest still load.")
		fmt.Println("Fix the domain/alias (must be a valid hostname) or upstream/root fields above,")
		fmt.Println("then re-run this check until it's clean before upgrading prod.")
		os.Exit(1)
	}
	fmt.Println("All good — every site would load on the new version.")
}

// cmdAgent runs the privileged orchestration agent. It holds the Docker
// socket and serves the agent API on a unix socket, authenticated with
// the shared key the control plane writes to <data>/agent.key.
func cmdAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	socket := fs.String("socket", "/run/orxies/agent.sock", "unix socket to listen on")
	dataDir := fs.String("data", "/etc/orxies", "data dir holding agent.key")
	keyPath := fs.String("key", "", "shared secret path (default <data>/agent.key)")
	logLevel := fs.String("log-level", "info", "log level")
	_ = fs.Parse(args)
	configureLogging(*logLevel)
	if *keyPath == "" {
		*keyPath = filepath.Join(*dataDir, "data", "agent.key")
	}
	// The control plane generates the key; wait for it to appear.
	secret := waitForKey(*keyPath, 60*time.Second)
	if secret == "" {
		fatal("agent key not found at %s (is the control plane running?)", *keyPath)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	srv := agent.NewServer(agent.CLIRunner{}, []byte(secret))
	if h := (agent.CLIRunner{}).Health(ctx); !h.Docker {
		slog.Warn("docker not reachable from agent", "detail", h.Detail)
	}
	slog.Info("orxies-agent listening", "socket", *socket, "version", Version)
	if err := srv.Serve(ctx, *socket); err != nil {
		fatal("agent: %v", err)
	}
	slog.Info("orxies-agent shutdown complete")
}

// ensureAgentKey reads (or creates, once) the shared agent secret as a
// 64-char hex string safe to carry in an HTTP header.
func ensureAgentKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return string(b), nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := hex.EncodeToString(raw)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) { // lost a race — read what's there
			b, rerr := os.ReadFile(path)
			return string(b), rerr
		}
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(key); err != nil {
		return "", err
	}
	return key, nil
}

func waitForKey(path string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for {
		if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
			return string(b)
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data", "/etc/orxies", "data directory")
	sitesDir := fs.String("sites", "", "sites directory (default <data>/sites)")
	certsDir := fs.String("certs", "", "ACME cert storage (default <data>/certs)")
	wwwDir := fs.String("www", "", "static-sites base dir (default <data>/www)")
	agentSock := fs.String("agent-socket", "/run/orxies/agent.sock", "orxies-agent unix socket")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	_ = fs.Parse(args)

	configureLogging(*logLevel)
	slog.Info("orxies starting", "version", Version, "data", *dataDir)

	if *sitesDir == "" {
		*sitesDir = filepath.Join(*dataDir, "sites")
	}
	if *certsDir == "" {
		*certsDir = filepath.Join(*dataDir, "certs")
	}
	if *wwwDir == "" {
		*wwwDir = filepath.Join(*dataDir, "www")
	}
	// Persistent platform state (SQLite DB + agent key) lives in the
	// mounted data/ subdir so it survives container recreation.
	stateDir := filepath.Join(*dataDir, "data")
	for _, d := range []string{*dataDir, *sitesDir, *certsDir, *wwwDir, stateDir} {
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

	// Platform state + deploy orchestration (Phase 3). The shared key is
	// written here so the (privileged) agent can read it and trust us.
	agentKey, err := ensureAgentKey(filepath.Join(stateDir, "agent.key"))
	if err != nil {
		fatal("agent key: %v", err)
	}
	db, err := pstore.Open(filepath.Join(stateDir, "orxies.db"))
	if err != nil {
		fatal("open platform store: %v", err)
	}
	defer db.Close()
	secrets, err := secretbox.Open(filepath.Join(stateDir, "secretbox.key"))
	if err != nil {
		fatal("secretbox: %v", err)
	}
	reposDir := filepath.Join(stateDir, "repos")
	if err := os.MkdirAll(reposDir, 0o700); err != nil {
		fatal("mkdir repos: %v", err)
	}
	deployMgr := &deploy.Manager{
		Store:    db,
		Agent:    agent.NewClient(*agentSock, agentKey),
		SitesDir: *sitesDir,
		ReposDir: reposDir,
		Secrets:  secrets,
	}

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
		DB:            db,
		Deploy:        deployMgr,
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
	reloadNow := func() {
		// Force a synchronous reload after a UI edit or a deploy so the
		// next request reflects the change. Reuses the watcher's path.
		sites, _ := config.LoadSites(*sitesDir)
		store.Replace(sites)
		watcher.OnReload(sites, nil)
	}
	uiSrv.ReloadCallback = func(_ context.Context) { reloadNow() }
	deployMgr.OnChange = reloadNow

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

	// Public deploy-on-push webhook sits in front of the reverse-proxy
	// router on the edge listeners (falls through to routing for all
	// other paths).
	edge := webhook.New(db, uiSrv.TriggerDeploy, router)

	deps := &server.Deps{
		Global:           g,
		Store:            store,
		Watcher:          watcher,
		Router:           router,
		Edge:             edge,
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
	slog.Info("orxies shutdown complete")
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
	fmt.Fprintf(os.Stderr, "orxies: "+format+"\n", args...)
	os.Exit(1)
}
