# Moteur factice jetable du spike SP-06. Même pattern que spike/proxy/Dockerfile :
# `go mod tidy` résout et télécharge les dépendances à la construction de
# l'image (pas de go.sum committé), acceptable pour un spike jetable.
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
