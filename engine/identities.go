// Identity parsing and lazy passphrase handling follow cmd/age at v1.3.2.
// Portions Copyright 2019 The age Authors. All rights reserved.
// See AGE-LICENSE.txt for the upstream BSD license.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"filippo.io/age/tag"
	"golang.org/x/crypto/ssh"
)

func boundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	contents, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		clear(contents)
		return nil, fmt.Errorf("Key file exceeds %d bytes", limit)
	}
	return contents, nil
}

func parseRecipient(line string, c *connection) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(line, "age1tag1"), strings.HasPrefix(line, "age1tagpq1"):
		return tag.ParseRecipient(line)
	case strings.HasPrefix(line, "age1pq1"):
		return age.ParseHybridRecipient(line)
	case strings.HasPrefix(line, "age1") && strings.Count(line, "1") > 1:
		return plugin.NewRecipient(line, c.ui())
	case strings.HasPrefix(line, "age1"):
		return age.ParseX25519Recipient(line)
	case strings.HasPrefix(line, "ssh-"):
		return agessh.ParseRecipient(line)
	default:
		return nil, errors.New("Unsupported recipient format")
	}
}

func loadRecipients(r request, c *connection) ([]age.Recipient, error) {
	sources := []string{r.Recipients}
	for _, path := range r.RecipientFiles {
		b, err := boundedFile(path, 16<<20)
		if err != nil {
			return nil, err
		}
		sources = append(sources, string(b))
	}
	var recs []age.Recipient
	seen := map[string]bool{}
	for _, source := range sources {
		scanner := bufio.NewScanner(strings.NewReader(source))
		scanner.Buffer(make([]byte, 8192), 8193)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !utf8.ValidString(line) {
				return nil, errors.New("Recipient files must be UTF-8")
			}
			if seen[line] {
				continue
			}
			seen[line] = true
			rec, err := parseRecipient(line, c)
			if err != nil {
				// Match the CLI: skip well-formed unsupported SSH public keys,
				// but reject malformed keys without echoing possible secrets.
				if strings.HasPrefix(line, "ssh-") || strings.HasPrefix(line, "ecdsa-") || strings.HasPrefix(line, "sk-") {
					if key, _, _, _, e := ssh.ParseAuthorizedKey([]byte(line)); e == nil {
						c.send(response{Type: "status", Message: "Skipped unsupported SSH key type " + key.Type()})
						continue
					}
				}
				return nil, fmt.Errorf("Invalid recipient on line %d. Use a public age, SSH, tag, or plugin key; never paste a secret identity here.", lineNo)
			}
			recs = append(recs, rec)
		}
		if err := scanner.Err(); err != nil {
			return nil, errors.New("Recipient line is too long (maximum 8 KiB)")
		}
	}
	return recs, nil
}

func checkProtection(mode string, r age.Recipient) error {
	if mode == "auto" || mode == "" {
		return nil
	}
	kind := "plugin"
	if named, ok := r.(*encodedRecipient); ok {
		r = named.Recipient
	}
	switch r.(type) {
	case *age.X25519Recipient:
		kind = "classic"
	case *age.HybridRecipient:
		kind = "pq"
	case *agessh.RSARecipient, *agessh.Ed25519Recipient:
		kind = "ssh"
	default:
		if s, ok := r.(fmt.Stringer); ok {
			if strings.HasPrefix(s.String(), "age1tagpq1") {
				kind = "post-quantum P-256 tag"
			} else if strings.HasPrefix(s.String(), "age1tag1") {
				kind = "P-256 tag"
			}
		}
	}
	if mode != kind {
		return fmt.Errorf("A %s recipient does not match the selected %s protection. Choose the matching type or Detect from keys.", kind, mode)
	}
	return nil
}

func parseIdentityLines(contents []byte, c *connection) ([]age.Identity, error) {
	if len(contents) > 16<<20 {
		return nil, errors.New("Identity file exceeds 16 MiB")
	}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 8192), 64*1024)
	var ids []age.Identity
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var id age.Identity
		var err error
		switch {
		case strings.HasPrefix(line, "AGE-PLUGIN-"):
			id, err = plugin.NewIdentity(line, c.ui())
		case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
			id, err = age.ParseHybridIdentity(line)
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			id, err = age.ParseX25519Identity(line)
		default:
			return nil, errors.New("Unrecognized secret identity. Choose a private identity file, not a public recipients file.")
		}
		if err != nil {
			return nil, errors.New("Malformed secret identity")
		}
		ids = append(ids, id)
	}
	if scanner.Err() != nil || len(ids) == 0 {
		return nil, errors.New("No valid identities were found")
	}
	return ids, nil
}

func loadIdentities(r request, c *connection) ([]age.Identity, error) {
	var all []age.Identity
	for _, path := range r.IdentityFiles {
		data, err := boundedFile(path, 16<<20)
		if err != nil {
			return nil, err
		}
		ids, err := parseIdentityData(path, data, c)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("Cannot open identity %q: %w", path, err)
		}
		all = append(all, ids...)
	}
	if r.IdentityText != "" {
		data := []byte(r.IdentityText)
		ids, err := parseIdentityData("pasted identity", data, c)
		clear(data)
		if err != nil {
			return nil, err
		}
		all = append(all, ids...)
	}
	for _, name := range r.Plugins {
		id, err := plugin.NewIdentityWithoutData(strings.TrimSpace(name), c.ui())
		if err != nil {
			return nil, errors.New("Invalid plugin name")
		}
		all = append(all, id)
	}
	return all, nil
}

func parseIdentityData(name string, data []byte, c *connection) ([]age.Identity, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(data, []byte("age-encryption")) || bytes.HasPrefix(trimmed, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		encrypted, err := io.ReadAll(io.LimitReader(unarmor(bytes.NewReader(data)), 16<<20+1))
		if err != nil {
			return nil, err
		}
		if len(encrypted) > 16<<20 {
			return nil, errors.New("Encrypted identity exceeds 16 MiB")
		}
		return []age.Identity{&encryptedIdentity{contents: encrypted, c: c, name: name}}, nil
	}
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		if len(data) > 16<<10 {
			return nil, errors.New("SSH private key exceeds 16 KiB")
		}
		id, err := agessh.ParseIdentity(data)
		if missing, ok := err.(*ssh.PassphraseMissingError); ok {
			copied := bytes.Clone(data)
			if missing.PublicKey == nil {
				if publicBytes, e := boundedFile(name+".pub", 8192); e == nil {
					missing.PublicKey, _, _, _, _ = ssh.ParseAuthorizedKey(publicBytes)
				}
			}
			if missing.PublicKey != nil {
				locked, e := agessh.NewEncryptedSSHIdentity(missing.PublicKey, copied, func() ([]byte, error) {
					value, e := c.ask("Passphrase for SSH identity "+name, true, "", "")
					return []byte(value), e
				})
				if e != nil {
					return nil, e
				}
				return nameSSHIdentity(locked, locked.Recipient(), missing.PublicKey), nil
			}
			// Legacy PEM keys may not carry their public key. The CLI reads a
			// sibling .pub file; if absent the GUI can unlock the key directly.
			value, e := c.ask("Passphrase for SSH identity "+name, true, "", "")
			if e != nil {
				return nil, e
			}
			raw, e := ssh.ParseRawPrivateKeyWithPassphrase(copied, []byte(value))
			clear(copied)
			if e != nil {
				return nil, errors.New("Incorrect SSH key passphrase")
			}
			return sshRawIdentity(raw)
		}
		if err != nil {
			return nil, errors.New("Malformed or unsupported SSH private key")
		}
		_ = id
		raw, e := ssh.ParseRawPrivateKey(data)
		if e != nil {
			return nil, errors.New("Cannot read SSH private key")
		}
		return sshRawIdentity(raw)
	}
	return parseIdentityLines(data, c)
}

type lazyScrypt struct{ passphrase func() (string, error) }

func (i *lazyScrypt) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, stanza := range stanzas {
		if stanza.Type == "scrypt" && len(stanzas) != 1 {
			return nil, errors.New("A passphrase recipient must be the only recipient")
		}
	}
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, age.ErrIncorrectIdentity
	}
	pass, err := i.passphrase()
	if err != nil {
		return nil, err
	}
	identity, err := age.NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	key, err := identity.Unwrap(stanzas)
	if errors.Is(err, age.ErrIncorrectIdentity) {
		return nil, errors.New("Incorrect passphrase")
	}
	return key, err
}

type encryptedIdentity struct {
	contents   []byte
	identities []age.Identity
	name       string
	c          *connection
}

func (i *encryptedIdentity) unlock() error {
	if i.identities != nil {
		return nil
	}
	reader, err := age.Decrypt(bytes.NewReader(i.contents), &lazyScrypt{passphrase: func() (string, error) { return i.c.ask("Passphrase for protected identity "+i.name, true, "", "") }})
	if err != nil {
		return fmt.Errorf("Cannot unlock protected identity: %w", err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, 16<<20+1))
	if err != nil {
		return err
	}
	defer clear(plaintext)
	i.identities, err = parseIdentityLines(plaintext, i.c)
	return err
}
func (i *encryptedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if err := i.unlock(); err != nil {
		return nil, err
	}
	for _, id := range i.identities {
		key, err := id.Unwrap(stanzas)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		return key, err
	}
	return nil, age.ErrIncorrectIdentity
}
func identitiesToRecipients(ids []age.Identity) ([]age.Recipient, error) {
	var recs []age.Recipient
	for _, id := range ids {
		switch id := id.(type) {
		case *identityWithPublic:
			recs = append(recs, id.public)
		case *age.X25519Identity:
			recs = append(recs, id.Recipient())
		case *age.HybridIdentity:
			recs = append(recs, id.Recipient())
		case *agessh.RSAIdentity:
			recs = append(recs, id.Recipient())
		case *agessh.Ed25519Identity:
			recs = append(recs, id.Recipient())
		case *agessh.EncryptedSSHIdentity:
			recs = append(recs, id.Recipient())
		case *plugin.Identity:
			recs = append(recs, id.Recipient())
		case *encryptedIdentity:
			if err := id.unlock(); err != nil {
				return nil, err
			}
			sub, err := identitiesToRecipients(id.identities)
			if err != nil {
				return nil, err
			}
			recs = append(recs, sub...)
		default:
			return nil, errors.New("Identity cannot be converted into recipients")
		}
	}
	return recs, nil
}
