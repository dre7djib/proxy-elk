# Static linux binaries, one tar.gz per arch, checksums of the archives.
# VERSION=v1.2.3 make release
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: release clean
release: clean
	for arch in amd64 arm64; do \
	  name=proxy-elk_$(VERSION)_linux_$$arch; \
	  mkdir -p dist/$$name || exit 1; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
	    -o dist/$$name/proxy ./cmd/proxy || exit 1; \
	  cp deploy/systemd/proxy-elk.service deploy/systemd/proxy.yaml deploy/systemd/install.sh dist/$$name/; \
	  tar -C dist -czf dist/$$name.tar.gz $$name || exit 1; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS

clean:
	rm -rf dist
