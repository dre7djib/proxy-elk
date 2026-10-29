# Disposable dummy engine for the SP-06 spike. Same pattern as spike/proxy/Dockerfile:
# `go mod tidy` resolves and downloads dependencies at image
# build time (no committed go.sum), acceptable for a disposable spike.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go keys.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /engine .

FROM alpine:3.20
RUN apk add --no-cache curl
COPY --from=build /engine /engine
EXPOSE 8080
ENTRYPOINT ["/engine"]
