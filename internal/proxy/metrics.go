package proxy

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "proxy_http_requests_total",
	Help: "Total HTTP requests served by the proxy, by response code and path.",
}, []string{"code", "path"})

// MetricsHandler exposes process/Go runtime metrics plus proxy_http_requests_total
// for Prometheus scraping. Unauthenticated, as scrapers rarely carry proxy creds.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// Instrument wraps a handler to count requests by status code and request path.
func Instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		httpRequestsTotal.WithLabelValues(strconv.Itoa(rec.status), r.URL.Path).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
