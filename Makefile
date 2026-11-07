# Static linux binaries + checksums. VERSION=1.2.3 make release
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: release clean
release:
	mkdir -p dist
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/proxy-linux-$$arch ./cmd/proxy || exit 1; \
	done
	cd dist && sha256sum proxy-linux-amd64 proxy-linux-arm64 > SHA256SUMS

clean:
	rm -rf dist
