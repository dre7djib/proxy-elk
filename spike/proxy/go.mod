module proxyelk/spike/proxy

go 1.23

// Pinned on purpose: newer releases (v3.4.9+) need a Go compiler
// newer than golang:1.23-alpine (see proxy/Dockerfile).
require github.com/go-ldap/ldap/v3 v3.4.8

// Short-lived token (JWT RS256) issued on
// POST /_spike/identity-token.
require github.com/golang-jwt/jwt/v5 v5.2.1
