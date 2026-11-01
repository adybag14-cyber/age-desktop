# age CLI workflows in the desktop interface

The reference for this version is the official **age 1.3.2** CLI, its manual, `age-keygen`, and `age-inspect`. The UI is native Rust/Iced; a local stdio adapter calls the pinned official Go age library. Cryptography is not reimplemented in the GUI.

## Choosing encryption

Age fixes payload encryption to **ChaCha20-Poly1305**. Its recipient mechanisms protect the file key; it does not offer an AES-versus-ChaCha cipher flag. The GUI makes the actual choices explicit:

| GUI choice | Key mechanism and accepted input |
|---|---|
| Post-quantum | Hybrid ML-KEM-768 + X25519, using `age1pq1…` recipients |
| Classic | X25519 `age1…` recipients |
| Passphrase | Scrypt-derived protection, with a user-entered or generated passphrase |
| SSH | `ssh-ed25519` and `ssh-rsa` public keys |
| Plugin / hardware key | An installed plugin's public recipient, identity, or documented data-less plugin name |
| Detect from recipient keys | Determine recipient types from supplied keys, including native P-256 tag and ML-KEM + P-256 tag recipients; age still rejects incompatible combinations |

Selecting a type is enforced by the engine. A classic key cannot silently satisfy a Post-quantum selection. Multiple recipients are supported, but mixing post-quantum and classic recipients is rejected by age's label rules. Passphrase encryption cannot be combined with recipients.

## Option mapping

| CLI operation / option | Desktop equivalent |
|---|---|
| `-e`, `--encrypt` | Encrypt view |
| `-d`, `--decrypt` | Decrypt view |
| `-r`, `--recipient` (repeatable) | Recipient public-key editor; one key per line |
| `-R`, `--recipients-file` (repeatable) | Import recipient files; selected files are listed and individually removable |
| `-R -` | Paste recipients into the editor |
| `-e -i`, `--encrypt --identity` (repeatable) | Use my identities / plugins → Add identity files |
| `-d -i`, `--decrypt --identity` (repeatable) | Add identity files in Decrypt |
| `-i -` | Paste identity from the clipboard; the value stays hidden and can be cleared |
| Protected native identity files | Password prompt when the selected identity is needed |
| Encrypted SSH identity files | Password prompt; public-key matching avoids unnecessary prompts where the public key is available |
| `-j PLUGIN` | Plugin name field; multiple names can be separated by commas |
| Plugin messages, PIN requests, confirmations, touch waits | Status area and native modal prompts; cancellation supervises the operation's process tree on Windows |
| `-p`, `--passphrase` | Passphrase protection; confirmation and a secure random generator |
| `-a`, `--armor` | Text-friendly output switch; Text mode is armored automatically |
| `-o`, `--output` | Folder for a batch, or Save as for a single input filename |
| CLI output replacement | Replace existing outputs switch, followed by confirmation of the concrete destination list |
| Standard input / output | Text & clipboard, with Copy result and Save result; Files handles binary data |
| `--version` | Tools & settings → Check engine version |
| `--help` / manual | How it works and this mapping |
| `age-keygen` | Your keys → Classic identity → Create & save |
| `age-keygen -pq` | Your keys → Post-quantum identity → Create & save |
| `age-keygen -o` | Native identity-save dialog |
| `age-keygen -y` | Open identity files → public recipients |
| `age-keygen -y -o` | Export recipients file |
| `age-inspect` | Inspect view, or Inspect encryption details from Decrypt |
| `age-inspect --json` | Copy JSON / Save JSON |

Recipient files accept blank lines and `#` comments. Valid unsupported SSH public-key types are skipped with a status message, following age; malformed recipients are rejected without echoing their contents.

## Intentional GUI behavior

- The GUI defaults to post-quantum protection for new encryption workflows and key generation. Choose Classic for older age installations.
- Decrypt automatically requests a passphrase for a passphrase-encrypted input, including when identity files are selected for another file in the same batch. The CLI rejects some such flag combinations instead.
- Existing outputs are preserved by default. Replacement requires an explicit choice and confirmation. Selected input files, identity files, and recipient files are protected from replacement, including hard-link aliases. Key creation never replaces an existing identity.
- Plaintext entry is limited to 1 MiB and armored input to 2 MiB. Binary output is not silently coerced into text; use Files for binary or larger data. Files are streamed.
- Passphrases entered for new encryption/protected keys require at least 12 characters. The generator creates 24 cryptographically random bytes encoded as a 32-character URL-safe string (192 bits), rather than the CLI's word-based generator.
- The UI does not interpret shell commands, process substitutions, redirections, or `curl`. GitHub `.keys` downloads can be imported as recipient files. Those downloads are a separate shell/browser operation, not an age flag.
- Plugin-specific installation, key provisioning, and hardware access remain the responsibility of the selected plugin. Standard age plugin interactions are implemented and tested with a synthetic plugin; physical hardware tokens require separate validation.
- SSH agent access is not supported by age. A token holding an SSH key is distinct from an age hardware-token plugin.

The Equivalent age command disclosure explains selected options without putting passphrases, PINs, or pasted private keys into the command.

## Primary references

- [age 1.3.2 README](https://github.com/FiloSottile/age/blob/v1.3.2/README.md)
- [age manual](https://github.com/FiloSottile/age/blob/v1.3.2/doc/age.1)
- [age Go API](https://pkg.go.dev/filippo.io/age@v1.3.2)
- [Official plugin client API](https://github.com/FiloSottile/age/blob/v1.3.2/plugin/client.go)
- [age format specification](https://age-encryption.org/v1)
