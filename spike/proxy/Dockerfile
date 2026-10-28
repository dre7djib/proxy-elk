# Proxy jetable du spike SP-02/SP-03. Image minimale.
# `go mod tidy` résout et télécharge github.com/go-ldap/ldap/v3 (F4, SP-03) et
# écrit go.sum à la construction : pas de go.sum committé, nécessite un accès
# réseau au moment du `docker compose build` (acceptable pour un spike,
# non reproductible à l'octet près).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /proxy .

FROM alpine:3.20
RUN apk add --no-cache curl
COPY --from=build /proxy /proxy
EXPOSE 9200
ENTRYPOINT ["/proxy"]
