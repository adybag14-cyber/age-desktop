# Dependency review

Checked 1 November 2026 against RustSec database commit `2295466c4e9df26647fd67d8fa1c705ac2fc7f81` (30 October 2026).

**Known vulnerability findings: 0. Informational warnings: 9.** This is a dependency scan, not an independent security audit.

The initial graph included RSA and P-256/HPKE dependencies that this application did not use. The final graph pins the age 0.11.5 classic-format patch, disables SSH, and removes those stacks. It also updates wayland-scanner to 0.31.11 / quick-xml to 0.41.0 and event-listener to 5.4.2.

| Dependency | Advisory | Category |
|---|---|---|
| basic-toml 0.1.10 | RUSTSEC-2026-0374 | unmaintained |
| paste 1.0.15 | RUSTSEC-2024-0436 | unmaintained |
| proc-macro-error2 2.0.1 | RUSTSEC-2026-0173 | unmaintained |
| rustybuzz 0.20.1 | RUSTSEC-2026-0206 | unmaintained |
| ttf-parser 0.25.1 | RUSTSEC-2026-0192 | unmaintained |
| zbus_names 4.3.5 | RUSTSEC-2026-0371 | unmaintained |
| zvariant 5.15.1 | RUSTSEC-2026-0370 | unmaintained |
| zvariant_derive 5.15.1 | RUSTSEC-2026-0372 | unmaintained |
| lru 0.16.4 | RUSTSEC-2026-0253 | unsound |

The lru warning concerns panic safety when a cache key destructor panics during pop, followed by continued use after unwinding. It remains an upstream warning; it was not suppressed. Other listed warnings concern maintenance status. Platform-specific dependencies also appear because the lockfile covers all targets.

X25519 and passphrase APIs are the only encryption paths accepted by this application. Unsupported recipient types are rejected explicitly. No network client or cryptography subprocess is used by the app.

Reproduce with `cargo audit --json`. The full initial and final reports are retained in the local evidence folder.