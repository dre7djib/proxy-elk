// Proxy minimal du spike SP-02 : un passe-plat (reverse proxy transparent)
// entre Kibana et Elasticsearch, qui journalise chaque appel en JSON sur
// stdout. Aucune logique d'authentification ou d'autorisation ici : c'est
// le périmètre de SP-03 et du jalon J1. Les en-têtes (dont Authorization)
// traversent sans modification.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// logEntry est une ligne du journal des appels (une par requête).
type logEntry struct {
	Timestamp   string `json:"ts"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Query       string `json:"query,omitempty"`
	Status      int    `json:"status"`
	DurationMS  int64  `json:"duration_ms"`
	Security    bool   `json:"security"`
	KibanaIndex bool   `json:"kibana_index"`
}

// statusRecorder capture le code de statut HTTP écrit par le proxy, pour
// pouvoir le journaliser après coup.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func main() {
	upstream := getenv("UPSTREAM_URL", "http://elasticsearch:9200")
	listenAddr := getenv("LISTEN_ADDR", ":9200")

	target, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("UPSTREAM_URL invalide %q: %v", upstream, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = log.New(os.Stderr, "", log.LstdFlags)

	log.Printf("proxy SP-02 : écoute sur %s, relaie vers %s", listenAddr, upstream)
	if err := http.ListenAndServe(listenAddr, logMiddleware(proxy)); err != nil {
		log.Fatal(err)
	}
}

// logMiddleware enveloppe le proxy pour écrire une ligne JSON par appel,
// une fois la réponse renvoyée par Elasticsearch.
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		entry := logEntry{
			Timestamp:   start.UTC().Format(time.RFC3339Nano),
			Method:      r.Method,
			Path:        r.URL.Path,
			Query:       r.URL.RawQuery,
			Status:      rec.status,
			DurationMS:  time.Since(start).Milliseconds(),
			Security:    isSecurityCall(r.URL.Path),
			KibanaIndex: strings.Contains(r.URL.Path, ".kibana"),
		}

		writeLog(entry)
	})
}

// isSecurityCall repère les appels à l'API de sécurité d'Elasticsearch
// (authentification, rôles, privilèges...), utile pour SP-03 et F67.
func isSecurityCall(path string) bool {
	return strings.HasPrefix(path, "/_security") || strings.HasPrefix(path, "/_xpack/security")
}

func writeLog(entry logEntry) {
	b, err := json.Marshal(entry)
	if err != nil {
		log.Printf("erreur de journalisation: %v", err)
		return
	}
	b = append(b, '\n')
	if _, err := os.Stdout.Write(b); err != nil {
		log.Printf("erreur d'écriture du journal: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
