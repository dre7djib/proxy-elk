package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"proxy/internal/audit"
	"proxy/internal/auth"
	"proxy/internal/config"
	"proxy/internal/limits"
	"proxy/internal/proxy"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "config: %s\n", err)
		os.Exit(1)
	}

	path, err := configPath(os.Args[1:], os.Stderr)
	if err != nil {
		os.Exit(1) // configPath already reported the flag error
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
		os.Exit(1)
	}

	mux, err := buildMux(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "listening on %s\n", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, proxy.Instrument(mux)); err != nil {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", err)
		os.Exit(1)
	}
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
