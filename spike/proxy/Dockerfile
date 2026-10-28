# Proxy jetable du spike SP-02. Image minimale, pas de dépendances externes.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /proxy .

FROM alpine:3.20
RUN apk add --no-cache curl
COPY --from=build /proxy /proxy
EXPOSE 9200
ENTRYPOINT ["/proxy"]
