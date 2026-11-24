SHELL := /bin/bash
GO ?= go
CARGO ?= cargo
RUST_STABLE ?= 1.97.1
RUST_NIGHTLY ?= nightly-2026-07-16
# V6.3.0 AP-0: static musl profile (LD_PRELOAD immunity for the privileged core).
RUST_MUSL ?= $(RUST_STABLE)
MUSL_TARGET_X86_64 ?= x86_64-unknown-linux-musl
MUSL_TARGET_AARCH64 ?= aarch64-unknown-linux-musl
MUSL_TARGET ?= $(MUSL_TARGET_X86_64)

.PHONY: all test test-race fuzz-smoke security-audit go gateway rust-ebpf rust-core rust-core-musl rust-check rust-helper rust full clean
all: test go gateway

test:
	cd control && $(GO) test ./... && $(GO) vet ./...
	cd gateway && $(GO) test ./... && $(GO) vet ./...
	# V6.3.0 refactoring wave 2: check every JS module, including subdirectories.
	find control/web -name '*.js' -type f -exec node --check {} +
	bash ./scripts/security-audit.sh

security-audit:
	bash ./scripts/security-audit.sh

test-race:
	cd control && $(GO) test -race ./...
	cd gateway && $(GO) test -race ./...

fuzz-smoke:
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreResponseParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzPolicyDocumentParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzEncryptedEnvelopeParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzProcStatParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzL7NormalizerNeverPanics -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzL7ResponseInspectionPreservesWireBytes -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzL7InlineUpstreamParserNeverEscapesLocalHost -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreStyxFlowParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreTitanExecParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreLockdownStatusParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreLockdownEventsParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzParserCellPayload -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzWitnessCheckpointDecode -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzWitnessReceiptDecode -fuzztime=3s
	# V6.3.0 AP-0/AP-1/AP-2 rejecting-decoder fuzzers.
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreSelfGuardParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreExecInodeParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreBpfGuardParser -fuzztime=3s
	# V6.3.0 AP-3/AP-4/AP-5 rejecting-decoder fuzzers.
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreCrossViewParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreKernelHookParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCorePersistenceParser -fuzztime=3s
	# V6.3.0 AP-9/S09 TUF envelope fuzzer.
	cd control && $(GO) test -run=^$$ -fuzz=FuzzTufFeedManifest -fuzztime=3s
	# V6.3.0 AP-6/AP-7 DNS capture and PermitV1 rejecting parsers.
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreDnsParser -fuzztime=3s
	cd control && $(GO) test -run=^$$ -fuzz=FuzzPermitV1Decode -fuzztime=3s
	# V6.3.0 AP-9 (S12) high-priority security ring parser.
	cd control && $(GO) test -run=^$$ -fuzz=FuzzCoreSecCritParser -fuzztime=3s

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

# V6.3.0 AP-0: static musl core binary (no glibc, no LD_PRELOAD attack surface
# against Symbiote/OrBit-style userland preload rootkits). The artifact must be
# a statically linked ELF (both `ldd` spellings and `file` are accepted; a
# release host may print "statically linked" or "static-pie linked") and must
# not carry a single dynamic NEEDED entry before it may replace the core.
rust-core-musl:
	$(CARGO) +$(RUST_MUSL) build --locked --manifest-path rust/Cargo.toml -p gedefense-core --release --target $(MUSL_TARGET)
	mkdir -p dist
	install -m 0755 rust/target/$(MUSL_TARGET)/release/gedefense-core dist/gedefense-core-musl
	@if readelf -d dist/gedefense-core-musl 2>/dev/null | grep -q 'NEEDED'; then \
		echo "ERROR: musl core build carries a dynamic NEEDED entry" >&2; exit 1; \
	fi
	@if file dist/gedefense-core-musl | grep -Eq 'statically linked|static-pie linked'; then \
		echo "musl static core verified: dist/gedefense-core-musl"; \
	else \
		echo "ERROR: musl core build is not statically linked" >&2; exit 1; \
	fi

# V6.3.0: fast typecheck of the Linux core and the bpfel eBPF object without a
# kernel. Used on non-Linux dev hosts and by CI before the privileged builds.
rust-check:
	$(CARGO) check --locked --manifest-path rust/Cargo.toml --target $(MUSL_TARGET_X86_64) -p gedefense-common -p gedefense-core
	$(CARGO) +$(RUST_NIGHTLY) check --locked --manifest-path rust/Cargo.toml -p gedefense-ebpf --target bpfel-unknown-none -Z build-std=core

# POINT 2: privileged ephemeral parser-cell helper (own root systemd unit).
rust-helper:
	$(CARGO) +$(RUST_STABLE) test --locked --manifest-path rust/Cargo.toml -p gedefense-cell-helper
	$(CARGO) +$(RUST_STABLE) build --locked --manifest-path rust/Cargo.toml -p gedefense-cell-helper --release
	mkdir -p dist
	install -m 0755 rust/target/release/gedefense-cell-helper dist/gedefense-cell-helper

rust: rust-ebpf rust-core rust-helper
full: test go gateway rust

clean:
	rm -rf dist rust/target
