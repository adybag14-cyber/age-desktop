# Validation — age desktop 0.2.0

Validated locally on Windows x64, 1 November 2026. Rust 1.91.1 / MSVC, Go 1.27.3, official age 1.3.2 with x/crypto 0.56.0.

## Final binaries

| File | Bytes | SHA256 |
|---|---:|---|
| age-desktop.exe | 23625728 | 820533c8a36f004ae0e1849d41f73c46d7a868c7fec90f980db93adeadf9bf27 |
| age-engine.exe | 5543936 | 564932386f0bbd69c25f27fa3bd6a181ab469bd0b586ed8056a5da3dc478bb62 |
| age-inspect.exe | 3080192 | b54ad074a7d2b8944979c60c1d513a27f2d2abb5bc11514b20949d15dfe62c87 |
| age-plugin-pq.exe | 3101696 | 6b0459fb172a248bffffe0505f759825a2a35c4f1c5b3306e8f82b5016ef1cde |
| age-plugin-tag.exe | 3062272 | e89f99869b79f38fd83d0123eb948dc896141fcb9a04d0ac91a233b6708a159a |
| age-plugin-tagpq.exe | 3070464 | 69e647b15c3218392a07a2d299334ad1165b08a23a21f87a27596aa867a2682f |

The package contains these exact binaries. The synthetic test plugin is excluded. Go VCS stamping is disabled for reproducible helper builds; dependency versions are pinned by Cargo.lock, go.mod, and go.sum.

## Automated checks

- Rust formatting and Clippy with warnings denied: passed.
- Rust release integration suite: **17 passed, 0 failed, 0 ignored**.
- Go engine suite: **13 top-level tests passed**, including official age CLI interoperability; SSH and native key-type subcases also passed.
- Go module checksum verification: passed.
- Rust dependency audit: zero vulnerability-category findings, seven informational warnings.
- Go vulnerability scan: zero reachable vulnerabilities and zero imported-package findings; one unimported OpenPGP module advisory remains. See dependency-review.md.

Rust integration cases cover classic/PQ binary and armored multichunk round trips; protected identities and private-pipe prompts; multiple identity/recipient files; identity-as-recipient; passphrase text and auto-detection; wrong passwords/keys; late ciphertext corruption and truncation; explicit output names; no-clobber and confirmed replacement; input/key-file and hard-link protection; cancelled prompts and partial cleanup; empty files; partial batches; metadata-only inspection; plugin PIN/confirmation flows; and exact owned-plugin termination on Windows.

The Go tests additionally cover RSA and Ed25519 identities, encrypted OpenSSH keys, public-key export, pasted identities, mixed-recipient label rejection, secure passphrase generation, redacted errors, and tag-recipient acceptance in automatic mode without falsely labeling P-256 as X25519. Official age v1.3.2 encrypted and decrypted post-quantum files interoperably with the engine.

## Native Windows UI checks

The running 0.2.0 UI was exercised through Windows Computer Use, not a web mockup:

1. Opened the encryption selector and verified all six protection choices.
2. Selected Passphrase and Text & clipboard; typed a synthetic message and a confirmed passphrase.
3. Encrypted through Ctrl+Enter; verified armored output.
4. Used Decrypt this text; supplied the automatically requested masked passphrase; verified exact recovered text.
5. Selected post-quantum identity generation and enabled passphrase protection.
6. Created an identity with the native Save dialog, then exported its public recipient with another native Save dialog.
7. Verified the identity file is age-encrypted with scrypt and has a protected owner/SYSTEM DACL.
8. Official age accepted the GUI-exported recipient; the engine unlocked the GUI-generated protected identity and recovered the original file hash.
9. The native Inspector displayed mlkem768x25519, a post-quantum indication, binary encoding, and the correct 62-byte payload size.
10. Final executable inspection, light/dark screenshots, CPU/GPU rendering, and CPU fallback were checked after the final UI polish.

The GUI-generated-key round-trip plaintext SHA256 was:

```text
dff193801c34f929d29c6d82f43566905724a6caa5b892425a0fe3da26d485e4
```

Final UI polish keeps the primary action fixed at the bottom, wraps long public keys, captures shortcuts before focused controls, shows results after completion, and resets scrolling when switching views. Screenshots were inspected at the default 1160 x 800 client size. Minimum-size and native screen-reader qualification remain separate.

## Launch measurements

Three fresh processes per mode, sequentially launched. Timings run from Rust main to the first redraw. OS and driver caches were not flushed; these are **process-start measurements, not cold-disk benchmarks**. The encryption helper is not launched by an ordinary empty UI startup.

| Mode | First run | Median of 3 | Range | Confirmed renderer |
|---|---:|---:|---:|---|
| CPU | 146.453 ms | 144.057 ms | 143.002–146.453 ms | tiny-skia / CPU |
| GPU | 1059.627 ms | 926.501 ms | 913.097–1059.627 ms | Vulkan / NVIDIA RTX 4090 |
| Auto | 928.153 ms | 928.153 ms | 906.932–942.362 ms | Vulkan / NVIDIA RTX 4090 |

Final automatic fallback was also exercised by selecting Metal on Windows, where that GPU backend is unavailable: the app selected tiny-skia and reached its first redraw in 149.813 ms. The final dark CPU screenshot reached first redraw in 168.496 ms. No system-wide renderer setting was changed.

Evidence: evidence/launch-20261101-231224, evidence/v020-final-fallback, evidence/v020-final-dark, and the synthetic native-workflow files in evidence/v020-native. These files are local and excluded from Git and the distributable.

## Boundaries

Physical YubiKey/TPM/smart-card hardware was not certified. The standard age plugin protocol, secret/confirmation UI bridge, and Windows process-tree cancellation were tested using a synthetic plugin built on the official plugin API. Plugin-specific provisioning is external.

Windows is the qualified desktop target for this build. macOS/Linux runtime and descendant-process shutdown remain unqualified. The application has not undergone an independent security audit. The previous release report is preserved in validation-0.1.0.md.
