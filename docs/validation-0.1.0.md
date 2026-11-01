# Local validation — 1 November 2026

Final Windows x64 release executable:

```text
SHA256 d0016182ca1b62f7220680163c733b565bf875c2158b48ab345221699f4abfb3
Bytes  23626240
```

Rust 1.91.1, Windows MSVC target. Core application dependencies and the complete transitive graph are pinned by Cargo.toml and Cargo.lock.

## Checks

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --all-targets -j 8 -- -D warnings`: passed.
- `cargo test --release --locked -j 8 -- --include-ignored` with the official reference binary configured: **10 passed, 0 failed, 0 ignored**. Library, binary, and documentation compilation also passed.
- `cargo build --release --locked`: passed.
- `cargo audit`: **0 known vulnerability findings**, with 9 unsuppressed informational warnings. See [dependency review](dependency-review.md).

The tests cover binary and armored multi-chunk round trips; multiple recipients; passphrase encryption and wrong-password rejection; wrong identities; late ciphertext corruption and truncation; no-clobber behavior; cancelled jobs; key-file creation and non-overwrite; mixed-success batches; empty inputs; invalid recipients; and interoperability in both directions with the official Go age binary.

Reference: [age v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2). The downloaded Windows ZIP was checked against the release asset digest:

```text
f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7
```

## Native UI evidence

Windows Computer Use exercised the rendered native app, its real file dialogs, and keyboard input. It created a dedicated test identity, used “Encrypt to myself,” loaded a test document, encrypted it, selected an independent output folder, and decrypted it. The original and decrypted file had identical SHA256 hashes. Windows ACL inspection confirmed that generated identities and decrypted output have protected owner/SYSTEM access rules.

The initial visual pass identified a primary action below the initial viewport and a public key overflowing its editor. The final layout keeps the primary action visible at the default 1160 × 800 client size, and the recipient editor wraps long unbroken keys without changing their contents. Light and dark screenshots from the final executable were inspected directly.

An actual interaction test also identified Ctrl+Enter being consumed by a focused secondary button. The final app captures global shortcuts before child controls. On the exact final executable above, a fresh test file was loaded from its command-line path, a full public key was typed into the editor, the theme button was focused, and Ctrl+Enter successfully encrypted the file without activating that button. Official Go age then decrypted that exact GUI-produced file, matching its original SHA256:

```text
e06ad12db7c3069adbf450e6d149fa1d5d90f71ebfaccb7c045c784c236e2936
```

The earlier complete GUI round trip used the UI preview build; the final backend was separately covered by all 10 tests, and the final keyboard/wrapping changes were repeated against the exact release executable. Native screen-reader behavior, macOS, and Linux were not qualified. The window is scrollable below its default size; a minimum-size visual qualification was not completed.

## Launch and graphics measurements

Three fresh processes per mode, sequentially launched on this workstation. Timings start at Rust `main` and end at the first redraw event. Screenshot completion is recorded separately. OS filesystem and driver caches were not flushed; these are process-start measurements, **not a cold-disk benchmark**. The initial CPU preview before the final build measured 264.879 ms; final numbers below are from the exact executable whose hash appears above.

| Mode | First process | Median of 3 | Range | Confirmed renderer |
|---|---:|---:|---:|---|
| CPU | 181.431 ms | 153.425 ms | 152.402–181.431 ms | tiny-skia, CPU |
| GPU | 1351.957 ms | 941.997 ms | 921.021–1351.957 ms | Vulkan, NVIDIA GeForce RTX 4090 |
| Auto | 928.742 ms | 935.261 ms | 928.742–936.887 ms | Vulkan, NVIDIA GeForce RTX 4090 |

The first CPU screenshot completed at 190.707 ms, and subsequent CPU screenshots at approximately 163 ms. Launch-to-observation measurements, including process creation and polling, are retained in the JSON. During the startup query the CPU runs reported roughly 49–50 MiB process memory; GPU auto runs reported roughly 223–225 MiB. These are snapshots, not peak-memory bounds. A later CPU idle snapshot after a file operation was 35.7 MiB; over the adjacent five-second observation the process consumed 265.625 ms CPU time, so no claim of zero idle CPU is made.

Additional checks:

- `WGPU_BACKEND=dx12`: actual RTX 4090 / Direct3D 12 rendering, 775.975 ms first redraw.
- Simulated unavailable GPU backend (`WGPU_BACKEND=metal` on Windows, app in auto mode): successful automatic fallback to tiny-skia / CPU, 156.998 ms first redraw. No system-wide graphics setting was changed.
- Forced CPU mode bypasses wgpu initialization.
- Both renderers produced correct light-theme screenshots, and the final CPU renderer also produced the inspected dark-theme screenshot.

Evidence is retained locally under `evidence/launch-20261101-220748`, `evidence/probe-dx12`, `evidence/probe-metal`, and `evidence/dark-final`. Normal application launches do not produce diagnostic files.

## Scope

This is a working initial desktop release, not an independently audited encryption product. It supports X25519 identities/recipients and passphrases. SSH, plugins/hardware tokens, post-quantum recipients, encrypted identity files, and directory archiving are intentionally outside this build. Files are processed locally, and originals/existing outputs are preserved.
