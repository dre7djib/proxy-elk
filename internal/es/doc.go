// Package es relays Kibana's calls to Elasticsearch once a caller's
// identity is resolved and the ACL grants the index/action (J1-15, F2):
// the proxy never forwards the caller's own credentials upstream — it
// authenticates with a service account and impersonates the caller via
// es-security-runas-user.
package es
