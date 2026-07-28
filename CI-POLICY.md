# CI and Release Policy

## Grundsatz

Public CI erzeugt keine signierten Produktions-Beta-Artefakte. Es darf Quelltests und statische Prüfungen ausführen, besitzt aber keinen Release-Private-Key und keine Berechtigung zur Promotion.

## Zulässige CI-Aufgaben

- Go Unit-Tests, Vet und Race Detector;
- Frontend-/HTML-/Shell-Syntax;
- verbotene Muster und Dependency-Grenze;
- Rust `fmt`, `clippy` und Tests ausschließlich aus geprüftem Vendorbaum;
- eBPF-Build und Verifier auf dedizierten, gehärteten Runnern;
- SBOM-/Provenance-Vorbereitung ohne Signatur.

## Pinning

Jede CI-Action und jeder Container muss auf einen unveränderlichen Digest beziehungsweise Commit-SHA gepinnt sein. Bewegliche Major-Tags sind für Security- und Release-Jobs verboten.

## Produktionsrelease

Ein Produktions-Beta-Release entsteht ausschließlich auf einem kontrollierten Offline-Builder mit:

- geprüftem Source Snapshot;
- Toolchain-Lock;
- Cargo-Lock-Attest und Vendorbaum;
- Netzwerk-Namespace ohne externes Interface;
- getrenntem Offline-Signing-Schritt;
- manueller Zwei-Personen-Freigabe.
