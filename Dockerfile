# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -o /usr/local/bin/proxy ./cmd/proxy

FROM alpine:3.20
RUN adduser -D -u 65532 proxy
COPY --from=build /usr/local/bin/proxy /usr/local/bin/proxy
USER 65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/proxy", "-config", "/etc/proxy/proxy.yaml"]

# Run (operator mounts config + secrets as env vars, see README):
#   docker build -t proxy-elk .
#   docker run --rm -p 8080:8080 \
#     -e SESSION_SECRET=... -e ES_API_KEY=... \
#     -v "$PWD/configs/my-proxy.yaml:/etc/proxy/proxy.yaml:ro" \
#     proxy-elk
#   curl -sf localhost:8080/health
#   curl -sf localhost:8080/metrics | head
