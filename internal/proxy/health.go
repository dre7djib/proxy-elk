package proxy

import "net/http"

// HandleHealth reports liveness of the running process. It never checks ES
// reachability (F53 readiness-vs-liveness split) and is unauthenticated so
// orchestrators can probe it without credentials.
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok"))
}
