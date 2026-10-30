package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"proxy/internal/acl"
	"proxy/internal/audit"
	"proxy/internal/auth"
	"proxy/internal/config"
	"proxy/internal/limits"
	"proxy/internal/proxy"
)

func main() {
	flags, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		os.Exit(1) // parseFlags already reported the error
	}

	if flags.simulate {
		if err := runSimulate(flags, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
			os.Exit(1)
		}
		return
	}

	if err := run([]string{"-config", flags.configPath}, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "config: %s\n", err)
		os.Exit(1)
	}

	cfg, _, err := config.Load(flags.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
		os.Exit(1)
	}

	mux, err := buildMux(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
		os.Exit(1)
	}

	store := newPolicyStore()
	if err := store.Reload(flags.configPath, os.Stderr); err != nil {
		os.Exit(1)
	}
	watchSIGHUP(store, flags.configPath)

	fmt.Fprintf(os.Stderr, "listening on %s\n", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, proxy.Instrument(mux)); err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
		os.Exit(1)
	}
}

// cliFlags is every flag the binary accepts: -config always; the rest
// only matter with -simulate (F22).
type cliFlags struct {
	configPath string
	simulate   bool
	subject    string
	groups     string
	index      string
	action     string
	ip         string
	method     string
	time       string
}

func parseFlags(args []string, stderr io.Writer) (cliFlags, error) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f cliFlags
	fs.StringVar(&f.configPath, "config", "./configs/proxy.yaml", "config file")
	fs.BoolVar(&f.simulate, "simulate", false, "simulate an ACL decision instead of starting the server (F22)")
	fs.StringVar(&f.subject, "subject", "", "simulate: caller subject")
	fs.StringVar(&f.groups, "groups", "", "simulate: comma-separated caller groups")
	fs.StringVar(&f.index, "index", "", "simulate: index name")
	fs.StringVar(&f.action, "action", "", "simulate: read, write or cluster_admin")
	fs.StringVar(&f.ip, "ip", "", "simulate: caller IP (RemoteAddr), optional")
	fs.StringVar(&f.method, "method", "", "simulate: HTTP method, optional")
	fs.StringVar(&f.time, "time", "", "simulate: RFC3339 timestamp, optional (defaults to now)")
	if err := fs.Parse(args); err != nil {
		return cliFlags{}, err
	}
	return f, nil
}

// runSimulate loads the config, builds the ACL policy, and prints the
// Decide outcome for one request (F22): "allow <rule>" or the Decide
// error text. It never starts listening. The returned error is only for
// an invalid config or -time value (exit 1 from main); the decision
// itself is the printed line, not the exit code.
func runSimulate(f cliFlags, stdout, stderr io.Writer) error {
	cfg, _, err := config.Load(f.configPath)
	if err != nil {
		return err
	}
	policy, err := acl.Parse(cfg.ACL.Rules, cfg.ACL.KnownGroups, cfg.ACL.SystemIndices)
	if err != nil {
		return err
	}

	var groups []string
	if f.groups != "" {
		groups = strings.Split(f.groups, ",")
	}
	id := auth.Identity{Subject: f.subject, Groups: groups}

	ctx := acl.DecideContext{RemoteAddr: f.ip, Method: f.method, Time: time.Now()}
	if f.time != "" {
		t, err := time.Parse(time.RFC3339, f.time)
		if err != nil {
			return fmt.Errorf("-time: %w", err)
		}
		ctx.Time = t
	}

	name, decideErr := policy.DecideRule(id, ctx, []string{f.index}, acl.Action(f.action))
	if decideErr != nil {
		fmt.Fprintln(stdout, decideErr.Error())
		return nil
	}
	fmt.Fprintf(stdout, "allow %s\n", name)
	return nil
}

// PolicyStore holds the ACL policy currently in effect, replaced
// atomically by Reload (F23, SIGHUP). The zero value has no policy yet.
type PolicyStore struct {
	policy atomic.Pointer[acl.Policy]
}

func newPolicyStore() *PolicyStore { return &PolicyStore{} }

// Current returns the policy currently in effect, or nil before the
// first successful Reload.
func (s *PolicyStore) Current() *acl.Policy { return s.policy.Load() }

// Reload re-reads path and revalidates the whole config — same
// validation as startup — then, only on success, builds the ACL policy
// and swaps it in. The listener, sessions and already-loaded secrets are
// untouched either way. On failure it writes one line to stderr and
// keeps the previous policy.
func (s *PolicyStore) Reload(path string, stderr io.Writer) error {
	cfg, _, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "acl reload: %s\n", err)
		return err
	}
	policy, err := acl.Parse(cfg.ACL.Rules, cfg.ACL.KnownGroups, cfg.ACL.SystemIndices)
	if err != nil {
		fmt.Fprintf(stderr, "acl reload: %s\n", err)
		return err
	}
	s.policy.Store(policy)
	return nil
}

// watchSIGHUP reloads store from path every time the process receives
// SIGHUP, for as long as the process runs.
func watchSIGHUP(store *PolicyStore, path string) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for range sighup {
			store.Reload(path, os.Stderr)
		}
	}()
}

func configPath(args []string, stderr io.Writer) (string, error) {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "./configs/proxy.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *path, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	path, err := configPath(args, stderr)
	if err != nil {
		return err
	}
	cfg, warnings, err := config.Load(path)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	b, err := json.Marshal(cfg.Redacted())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s\n", b)
	return nil
}

// buildMux wires every enabled login route plus GET /auth/me onto a mux
// that denies everything else by default (F3's spirit, needed here to
// exercise the session at all). OIDC and LDAP share one Sessions: whichever
// login succeeds, OnSuccess issues the same cookie.
func buildMux(cfg *config.Config) (http.Handler, error) {
	oidcActive := cfg.OIDC.Issuer != ""
	ldapActive := cfg.LDAP.URL != "" || len(cfg.LDAP.URLs) > 0

	var sessions *auth.Sessions
	if oidcActive || ldapActive {
		ttl, err := time.ParseDuration(cfg.Session.TTL)
		if err != nil {
			return nil, fmt.Errorf("session.ttl: %w", err)
		}
		sessions = auth.NewSessions(auth.SessionConfig{
			Secret: []byte(cfg.Session.Secret),
			TTL:    ttl,
			Secure: strings.HasPrefix(cfg.OIDC.RedirectURL, "https://"),
		})
	}

	var jwtVerifier *auth.JWT
	if cfg.JWT.Issuer != "" {
		var err error
		jwtVerifier, err = auth.NewJWT(context.Background(), auth.JWTConfig{
			Issuer:      cfg.JWT.Issuer,
			Audience:    cfg.JWT.Audience,
			JWKSURL:     cfg.JWT.JWKSURL,
			GroupsClaim: cfg.JWT.GroupsClaim,
		})
		if err != nil {
			return nil, fmt.Errorf("jwt: %w", err)
		}
	}

	var limiter *limits.Limits
	if cfg.Limits.Default != nil || len(cfg.Limits.Roles) > 0 {
		var err error
		limiter, err = limits.Parse(cfg.Limits.Default, cfg.Limits.Roles, cfg.ACL.KnownGroups)
		if err != nil {
			return nil, fmt.Errorf("limits: %w", err)
		}
	}
	guard := &proxy.Guard{Limits: limiter, Counter: limits.NewCounter(), Sessions: sessions, JWT: jwtVerifier}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", proxy.HandleHealth)
	mux.HandleFunc("/healthz", proxy.HandleHealth)
	mux.Handle("/metrics", proxy.MetricsHandler())
	mux.Handle("/", guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "access denied", http.StatusForbidden)
	})))
	mux.HandleFunc("/auth/me", proxy.HandleMe(sessions, jwtVerifier))

	if oidcActive {
		provider, err := auth.Discover(context.Background(), auth.OIDCConfig{
			Issuer:       cfg.OIDC.Issuer,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			Scopes:       cfg.OIDC.Scopes,
			GroupsClaim:  cfg.OIDC.GroupsClaim,
		})
		if err != nil {
			return nil, fmt.Errorf("oidc discovery: %w", err)
		}
		login := &proxy.OIDCLogin{Provider: provider, OnSuccess: sessionOnSuccess(sessions, auth.MethodOIDC)}
		mux.HandleFunc("/auth/login", login.HandleLogin)
		mux.HandleFunc("/auth/callback", login.HandleCallback)
	}

	if ldapActive {
		groupCacheTTL, err := time.ParseDuration(cfg.LDAP.GroupCacheTTL)
		if err != nil {
			return nil, fmt.Errorf("ldap.group_cache_ttl: %w", err)
		}
		directory, err := auth.NewLDAP(auth.LDAPConfig{
			URL: cfg.LDAP.URL, URLs: cfg.LDAP.URLs, StartTLS: cfg.LDAP.StartTLS,
			BindDN: cfg.LDAP.BindDN, BindPassword: cfg.LDAP.BindPassword, BaseDN: cfg.LDAP.BaseDN,
			UserFilter: cfg.LDAP.UserFilter, GroupsBaseDN: cfg.LDAP.GroupsBaseDN, CAFile: cfg.LDAP.CAFile,
			InsecureAllowPlaintext: cfg.LDAP.InsecureAllowPlaintext,
			NestedGroups:           cfg.LDAP.NestedGroups,
			GroupCacheTTL:          groupCacheTTL,
		})
		if err != nil {
			return nil, fmt.Errorf("ldap: %w", err)
		}
		failureWindow, err := time.ParseDuration(cfg.LDAP.FailureWindow)
		if err != nil {
			return nil, fmt.Errorf("ldap.failure_window: %w", err)
		}
		lockoutFor, err := time.ParseDuration(cfg.LDAP.LockoutFor)
		if err != nil {
			return nil, fmt.Errorf("ldap.lockout_for: %w", err)
		}
		limiter := auth.NewLimiter(auth.LockoutConfig{
			MaxFailures:   cfg.LDAP.MaxFailures,
			FailureWindow: failureWindow,
			LockoutFor:    lockoutFor,
		})
		login := &proxy.LDAPLogin{Directory: directory, Limiter: limiter, OnSuccess: sessionOnSuccess(sessions, auth.MethodLDAP)}
		mux.HandleFunc("/auth/ldap", login.HandleLogin)
	}

	return audit.New(os.Stdout, cfg.Mask).Handler(sessions, jwtVerifier, mux), nil
}

// sessionOnSuccess issues the shared session cookie and redirects to
// /auth/me; it is the only place a successful login touches the response,
// shared by both OIDCLogin and LDAPLogin.
func sessionOnSuccess(sessions *auth.Sessions, method auth.Method) func(http.ResponseWriter, *http.Request, auth.Identity) {
	return func(w http.ResponseWriter, r *http.Request, id auth.Identity) {
		if err := sessions.Issue(w, id, method); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/auth/me", http.StatusFound)
	}
}
