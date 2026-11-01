# Dependency review — 0.2.0

Checked 1 November 2026. This is a dependency scan, not an independent security audit.

## Rust UI and supervisor

`cargo audit` reports **0 known vulnerability findings** and **7 informational warnings**:

| Dependency | Advisory | Category |
|---|---|---|
| paste 1.0.15 | RUSTSEC-2024-0436 | unmaintained |
| rustybuzz 0.20.1 | RUSTSEC-2026-0206 | unmaintained |
| ttf-parser 0.25.1 | RUSTSEC-2026-0192 | unmaintained |
| zbus_names 4.3.5 | RUSTSEC-2026-0371 | unmaintained |
| zvariant 5.15.1 | RUSTSEC-2026-0370 | unmaintained |
| zvariant_derive 5.15.1 | RUSTSEC-2026-0372 | unmaintained |
| lru 0.16.4 | RUSTSEC-2026-0253 | unsound |

The lru warning concerns panic safety for key types with a panicking destructor; it remains unsuppressed. Platform-specific dependencies are present in the cross-platform lockfile. The old Rust age backend and its crypto dependencies are no longer linked into this GUI.

## Official Go age engine

Pinned: age 1.3.2, Go 1.27.3, golang.org/x/crypto 0.56.0. The x/crypto patch removes the SSH channel DoS package findings GO-2026-6354 and GO-2026-6355; the app uses SSH key parsing and does not open SSH connections.

`govulncheck` reports **0 reachable vulnerabilities** and **0 findings in imported packages**. It reports the module-level OpenPGP advisory GO-2026-5932 because x/crypto contains that obsolete package. OpenPGP is not imported, called, or linked by this application.

Raw reports are retained locally in evidence/v020-rust-audit.json and evidence/v020-go-vulnerability-final.txt. The original pre-update Go report is retained separately.

## Process and output checks

Windows cancellation was tested against a real synthetic age plugin requesting a PIN: the test opens a handle to that exact live plugin, cancels the operation, and verifies its exit. The engine and descendants are assigned to an unnamed operation-owned Job Object before receiving a request.

Tests also cover no-clobber commits, explicit replacement, hard-link/source/identity protection, damaged ciphertext, protected key prompts, and removal of incomplete output. Physical hardware-token verification remains separate.
