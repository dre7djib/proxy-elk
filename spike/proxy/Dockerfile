# Disposable proxy for the SP-02/SP-03 spike. Minimal image.
# `go mod tidy` resolves and downloads github.com/go-ldap/ldap/v3 (F4, SP-03) and
# writes go.sum at build time: no committed go.sum, requires network
# access at `docker compose build` time (acceptable for a spike,
# not byte-for-byte reproducible).
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
