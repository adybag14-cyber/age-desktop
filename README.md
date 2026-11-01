# age desktop

A native **Rust + shadcn-iced** desktop interface for the official [age encryption format](https://github.com/FiloSottile/age). Version **0.2.0** brings current age workflows into a graphical interface: post-quantum and classic keys, SSH, passphrases, plugins, protected identities, text encryption, and inspection.

![age desktop](docs/screenshots/light.png)

## What you can do

- **Choose protection:** Post-quantum ML-KEM-768 + X25519, Classic X25519, Passphrase/scrypt, SSH Ed25519/RSA, Plugin/hardware, or automatic detection from recipient keys. Age's payload cipher remains ChaCha20-Poly1305.
- **Combine key sources:** paste recipients, import multiple recipient files, include your own identities, or supply a documented `-j` plugin name.
- **Unlock more identities:** multiple native/PQ/SSH files, encrypted age identities, encrypted SSH private keys, and pasted identities. Passwords and plugin PINs appear as masked prompts.
- **Encrypt files or text:** multiple files with streaming I/O; UTF-8 Text & clipboard with copy/save and automatic ASCII armor.
- **Choose output:** a folder for a batch or an explicit filename for one file. Optional output replacement has a confirmation dialog and protects selected input/key files.
- **Create and export keys:** classic or post-quantum identities, optional passphrase protection, public-recipient extraction and recipient-file export.
- **Inspect:** see the official age-inspect metadata without decrypting, and export its JSON. Inspection does not authenticate the ciphertext.
- **Use native graphics:** CPU software rendering, automatic GPU rendering with CPU fallback, or explicit GPU mode. Light and dark themes, native file dialogs, and keyboard controls.

See the complete [CLI-to-GUI mapping](docs/cli-parity.md), [validation](docs/validation.md), and [dependency review](docs/dependency-review.md).

## Run the portable app

Keep the entire Windows package together and run `age-desktop.exe`. The package contains the Rust UI, a local engine adapter, the official inspector, and age's PQ/tag compatibility plugins. Go, Rust, a browser runtime, and a separate age installation are not required on the destination machine.

The interface launches independently of the encryption engine. The engine starts only when needed for an operation and exits afterward.

```powershell
.\age-desktop.exe
.\age-desktop.exe --renderer cpu
.\age-desktop.exe --renderer gpu --dark
.\age-desktop.exe --decrypt 'C:\path\to\document.age'
.\age-desktop.exe --page keys
```

Default `auto` uses Iced's wgpu renderer and falls back to tiny-skia if initialization fails. `cpu` bypasses GPU initialization for the quickest launch. `gpu` requests the hardware renderer only. `ICED_BACKEND` and `WGPU_BACKEND` can also be used for renderer diagnostics. Tools & settings offers a rendering-mode selector with a session restart.

Keyboard: **Tab / Shift+Tab** move focus, **Ctrl+O** selects files, **Ctrl+Enter** starts the current operation, and **Ctrl+1 / 2 / 3** select Encrypt / Decrypt / Keys.

## Build from source on Windows

Requirements: Rust 1.88+ with the MSVC toolchain, Visual Studio C++ build tools, and Go with automatic toolchain downloads enabled. `engine/go.mod` pins **Go 1.27.3**, official **age 1.3.2**, and the dependency graph is recorded in `go.sum` and `Cargo.lock`.

```powershell
.\scripts\build.ps1
.\target\release\age-desktop.exe --renderer cpu

# Build the synthetic plugin fixture and run both test suites
.\scripts\build.ps1 -Test

# Optional reference CLI interoperability tests
$env:AGE_REFERENCE_BIN = 'C:\path\to\official\age.exe'
Push-Location engine
go test -count=1 ./...
Pop-Location

cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
.\scripts\benchmark.ps1 -Runs 3
.\scripts\package.ps1 -SkipBuild
```

The package script stages each version in its own `dist/<version>` directory and refuses to replace an existing versioned ZIP. The synthetic test plugin is never packaged.

## Architecture and file handling

The GUI, component tree, file-selection state, output safeguards, and process supervisor are Rust. The narrow Go adapter uses the official age library for encryption/key parsing and the official `age-inspect` executable for metadata. No cryptographic algorithms are implemented in the desktop project. `golang.org/x/crypto` is pinned to 0.56.0 to include the SSH channel fixes newer than age's original minimum dependency.

The engine communicates through a bounded JSON-lines protocol over private pipes. Passphrases, pasted identities, and plugin answers are not command arguments or environment variables. The engine's debug-transcript environment switch is removed. No server or background service is installed. Plugins are started only for user-selected recipients/identities/plugin names, never simply because an input header names a stanza type.

Rust creates a staging file beside the destination before calling the engine. Private output has Unix mode 0600 or a protected owner/SYSTEM DACL on Windows. Authentication, stream finalization, process success, and disk flush must succeed before the staged file is committed. Without explicit replacement the commit cannot clobber an existing destination. With replacement enabled, input/key-file aliases are rejected and unsuccessful operations preserve the previous destination. Earlier completed files in a batch remain saved if a later file fails or the operation is cancelled.

On Windows each operation runs in a private Job Object: cancellation and cleanup control only its owned engine and plugin descendants. Native Linux/macOS runtime and descendant-process qualification remain separate work. No process-name or global termination commands are used.

Secrets are cleared where the Rust application controls their storage; GUI libraries, the Go runtime, clipboard, and operating system can retain copies. Temporary-file deletion is not secure erasure, and crashes/forced termination can leave staging files. Keep secret identities in a protected location with a backup.

## Scope and evidence

This is an independent desktop application, not an official age release or an independently audited encryption product. Windows is locally tested. Hardware-token protocol interactions are implemented, but a physical token was not certified. Arbitrary plugin-specific setup commands and shell pipelines are not part of the GUI.

Normal launches write no diagnostic files. The explicit `--probe <directory>` option records a screenshot, renderer information, first-redraw timing, and exits. Benchmark results are fresh-process measurements; OS/driver caches are not flushed. The previous 0.1.0 measurements are retained in [historical validation](docs/validation-0.1.0.md).

Application source is BSD-3-Clause licensed. Dependencies and bundled fonts/icons retain their own licenses; notices are included in the portable package. [Library selection](docs/library-selection.md) documents the native GUI choice.
