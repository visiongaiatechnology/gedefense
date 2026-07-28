SHELL := /bin/bash
GO ?= go
CARGO ?= cargo
RUST_STABLE ?= 1.97.1
RUST_NIGHTLY ?= nightly-2026-07-16

.PHONY: all test test-race fuzz-smoke security-audit go gateway rust-ebpf rust-core rust full clean
all: test go gateway

test:
	cd control && $(GO) test ./... && $(GO) vet ./...
	cd gateway && $(GO) test ./... && $(GO) vet ./...
	node --check control/web/api.js
	node --check control/web/render.js
	node --check control/web/i18n.js
	node --check control/web/charts.js
	node --check control/web/app.js
	./scripts/security-audit.sh

security-audit:
	./scripts/security-audit.sh

test-race:
	cd control && $(GO) test -race ./...
	cd gateway && $(GO) test -race ./...

fuzz-smoke:
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreResponseParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzPolicyDocumentParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzEncryptedEnvelopeParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzProcStatParser -fuzztime=3s

go:
	mkdir -p dist
	cd control && CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o ../dist/gedefense-control .

gateway:
	mkdir -p dist
	cd gateway && CGO_ENABLED=1 $(GO) build -trimpath -buildvcs=false -ldflags="-s -w -buildid= -extldflags=-Wl,--build-id=none" -o ../dist/gedefense-access .

rust-ebpf:
	$(CARGO) +$(RUST_NIGHTLY) build --locked --manifest-path rust/Cargo.toml -p gedefense-ebpf --release --target bpfel-unknown-none -Z build-std=core
	mkdir -p dist
	install -m 0644 rust/target/bpfel-unknown-none/release/gedefense-ebpf dist/gedefense-ebpf

rust-core:
	$(CARGO) +$(RUST_STABLE) test --locked --manifest-path rust/Cargo.toml -p gedefense-common -p gedefense-core
	$(CARGO) +$(RUST_STABLE) build --locked --manifest-path rust/Cargo.toml -p gedefense-core --release
	mkdir -p dist
	install -m 0755 rust/target/release/gedefense-core dist/gedefense-core

rust: rust-ebpf rust-core
full: test go gateway rust

clean:
	rm -rf dist rust/target
