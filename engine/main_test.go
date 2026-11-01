package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/tag"
	"golang.org/x/crypto/ssh"
)

func testConnection(answers string) *connection {
	return &connection{input: bufio.NewScanner(strings.NewReader(answers)), output: json.NewEncoder(&bytes.Buffer{})}
}
func stage(t *testing.T, dir string) string {
	t.Helper()
	f, e := os.CreateTemp(dir, "stage-")
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	return f.Name()
}
func makeIdentity(t *testing.T, dir, kind string, protect bool) (string, string) {
	t.Helper()
	path := stage(t, dir)
	res, err := execute(request{Operation: "generate_key", Output: path, KeyKind: kind, ProtectKey: protect, Passphrase: "test-only meadow comet lantern river"}, testConnection(""))
	if err != nil {
		t.Fatal(err)
	}
	return path, res.PublicKeys[0]
}
func textRoundTrip(t *testing.T, recs string, ids []string, c *connection) {
	t.Helper()
	plain := "age desktop — Unicode and authenticated text ✓"
	enc, e := execute(request{Operation: "encrypt", Text: &plain, Recipients: recs, Protection: "auto"}, c)
	if e != nil {
		t.Fatal(e)
	}
	dec, e := execute(request{Operation: "decrypt", Text: enc.Text, IdentityFiles: ids}, c)
	if e != nil {
		t.Fatal(e)
	}
	if dec.Text == nil || *dec.Text != plain {
		t.Fatal("plaintext mismatch")
	}
}
func TestClassicAndPostQuantum(t *testing.T) {
	for _, kind := range []string{"classic", "pq"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			id, pub := makeIdentity(t, dir, kind, false)
			textRoundTrip(t, pub, []string{id}, testConnection(""))
			if kind == "pq" && !strings.HasPrefix(pub, "age1pq1") {
				t.Fatal("not a hybrid key")
			}
		})
	}
}
func TestProtectedIdentityPromptsAndExports(t *testing.T) {
	dir := t.TempDir()
	id, pub := makeIdentity(t, dir, "pq", true)
	c := testConnection("{\"prompt_id\":1,\"value\":\"test-only meadow comet lantern river\"}\n")
	textRoundTrip(t, pub, []string{id}, c)
	c = testConnection("{\"prompt_id\":1,\"value\":\"test-only meadow comet lantern river\"}\n")
	result, e := execute(request{Operation: "public_keys", IdentityFiles: []string{id}}, c)
	if e != nil {
		t.Fatal(e)
	}
	if len(result.PublicKeys) != 1 || result.PublicKeys[0] != pub {
		t.Fatal("incorrect public export")
	}
}
func TestRecipientFilesAndMultipleIdentities(t *testing.T) {
	dir := t.TempDir()
	first, a := makeIdentity(t, dir, "classic", false)
	second, b := makeIdentity(t, dir, "classic", false)
	unused, _ := makeIdentity(t, dir, "classic", false)
	rf := filepath.Join(dir, "recipients.txt")
	os.WriteFile(rf, []byte("# recipients\n"+a+"\n"+b+"\n"+a+"\n"), 0600)
	plain := "multi recipient test"
	enc, e := execute(request{Operation: "encrypt", Text: &plain, Protection: "classic", RecipientFiles: []string{rf}}, testConnection(""))
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{first, second} {
		dec, e := execute(request{Operation: "decrypt", Text: enc.Text, IdentityFiles: []string{unused, id}}, testConnection(""))
		if e != nil {
			t.Fatal(e)
		}
		if *dec.Text != plain {
			t.Fatal("mismatch")
		}
	}
}
func TestIdentityAsRecipientAndPastedIdentity(t *testing.T) {
	dir := t.TempDir()
	id, _ := makeIdentity(t, dir, "pq", false)
	secret, e := os.ReadFile(id)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(secret)
	plain := "encrypt to myself"
	enc, e := execute(request{Operation: "encrypt", Text: &plain, Protection: "pq", IdentityFiles: []string{id}}, testConnection(""))
	if e != nil {
		t.Fatal(e)
	}
	dec, e := execute(request{Operation: "decrypt", Text: enc.Text, IdentityText: string(secret)}, testConnection(""))
	if e != nil {
		t.Fatal(e)
	}
	if *dec.Text != plain {
		t.Fatal("mismatch")
	}
}
func TestPassphraseDetectionAndWrongPassword(t *testing.T) {
	plain := "password text"
	enc, e := execute(request{Operation: "encrypt", Text: &plain, Protection: "passphrase", Passphrase: "test-only meadow comet lantern river"}, testConnection(""))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = execute(request{Operation: "decrypt", Text: enc.Text, Passphrase: "wrong"}, testConnection("")); e == nil {
		t.Fatal("wrong password accepted")
	}
	dec, e := execute(request{Operation: "decrypt", Text: enc.Text}, testConnection("{\"prompt_id\":1,\"value\":\"test-only meadow comet lantern river\"}\n"))
	if e != nil {
		t.Fatal(e)
	}
	if *dec.Text != plain {
		t.Fatal("mismatch")
	}
}
func TestSSHKeysIncludingEncryptedOpenSSH(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			var private any
			if kind == "rsa" {
				k, e := rsa.GenerateKey(rand.Reader, 2048)
				if e != nil {
					t.Fatal(e)
				}
				private = k
			} else {
				_, k, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				private = k
			}
			public, e := ssh.NewPublicKey(rawPublic(private))
			if e != nil {
				t.Fatal(e)
			}
			pub := string(ssh.MarshalAuthorizedKey(public))
			for _, protected := range []bool{false, true} {
				var block *pem.Block
				if protected {
					block, e = ssh.MarshalPrivateKeyWithPassphrase(private, "fixture", []byte("test-only ssh password"))
				} else {
					block, e = ssh.MarshalPrivateKey(private, "fixture")
				}
				if e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(dir, kind+"-key")
				os.WriteFile(path, pem.EncodeToMemory(block), 0600)
				c := testConnection("{\"prompt_id\":1,\"value\":\"test-only ssh password\"}\n")
				textRoundTrip(t, pub, []string{path}, c)
				exported, e := execute(request{Operation: "public_keys", IdentityFiles: []string{path}}, testConnection(""))
				if e != nil {
					t.Fatal(e)
				}
				if strings.TrimSpace(exported.PublicKeys[0]) != strings.TrimSpace(pub) {
					t.Fatal("SSH public export mismatch")
				}
			}
		})
	}
}
func TestModeMismatchAndMixedQuantumRecipients(t *testing.T) {
	dir := t.TempDir()
	_, classic := makeIdentity(t, dir, "classic", false)
	_, pq := makeIdentity(t, dir, "pq", false)
	plain := "mode constraints"
	for _, req := range []request{{Operation: "encrypt", Text: &plain, Protection: "pq", Recipients: classic}, {Operation: "encrypt", Text: &plain, Protection: "classic", Recipients: pq}, {Operation: "encrypt", Text: &plain, Protection: "auto", Recipients: classic + "\n" + pq}, {Operation: "encrypt", Text: &plain, Protection: "passphrase", Recipients: classic, Passphrase: "must-not-mix"}} {
		if _, e := execute(req, testConnection("")); e == nil {
			t.Fatal("incompatible recipient selection accepted")
		}
	}
}
func TestFileAuthenticationAndOfficialAgeInterop(t *testing.T) {
	reference := os.Getenv("AGE_REFERENCE_BIN")
	if reference == "" {
		t.Skip("set AGE_REFERENCE_BIN for official CLI interoperability")
	}
	dir := t.TempDir()
	id, pub := makeIdentity(t, dir, "pq", false)
	input := filepath.Join(dir, "input.bin")
	data := bytes.Repeat([]byte("multi-chunk binary\x00\xff"), 18000)
	os.WriteFile(input, data, 0600)
	encrypted := stage(t, dir)
	if _, e := execute(request{Operation: "encrypt", Input: input, Output: encrypted, Protection: "pq", Recipients: pub}, testConnection("")); e != nil {
		t.Fatal(e)
	}
	output := filepath.Join(dir, "from-go.bin")
	if e := exec.Command(reference, "-d", "-i", id, "-o", output, encrypted).Run(); e != nil {
		t.Fatal(e)
	}
	actual, _ := os.ReadFile(output)
	if !bytes.Equal(actual, data) {
		t.Fatal("reference mismatch")
	}
	goEncrypted := filepath.Join(dir, "from-go.age")
	if e := exec.Command(reference, "-a", "-r", pub, "-o", goEncrypted, input).Run(); e != nil {
		t.Fatal(e)
	}
	restored := stage(t, dir)
	if _, e := execute(request{Operation: "decrypt", Input: goEncrypted, Output: restored, IdentityFiles: []string{id}}, testConnection("")); e != nil {
		t.Fatal(e)
	}
	actual, _ = os.ReadFile(restored)
	if !bytes.Equal(actual, data) {
		t.Fatal("bridge mismatch")
	}
	damaged, _ := os.ReadFile(encrypted)
	damaged[len(damaged)-1] ^= 1
	os.WriteFile(encrypted, damaged, 0600)
	if _, e := execute(request{Operation: "decrypt", Input: encrypted, Output: stage(t, dir), IdentityFiles: []string{id}}, testConnection("")); e == nil {
		t.Fatal("corrupt file accepted")
	}
}
func TestCancelledPrompt(t *testing.T) {
	c := testConnection("{\"prompt_id\":1,\"cancel\":true}\n")
	if _, e := c.ask("test", true, "", ""); e == nil {
		t.Fatal("cancelled prompt accepted")
	}
}
func TestInvalidRecipientDoesNotEchoSecret(t *testing.T) {
	_, e := loadRecipients(request{Recipients: "AGE-SECRET-KEY-sensitive-fixture"}, testConnection(""))
	if e == nil || strings.Contains(e.Error(), "sensitive-fixture") {
		t.Fatal("recipient error leaked input")
	}
}
func TestRandomPassphrase(t *testing.T) {
	a, e := execute(request{Operation: "generate_passphrase"}, testConnection(""))
	if e != nil {
		t.Fatal(e)
	}
	b, e := execute(request{Operation: "generate_passphrase"}, testConnection(""))
	if e != nil {
		t.Fatal(e)
	}
	if len(*a.Text) != 32 || *a.Text == *b.Text {
		t.Fatal("unexpected password generation")
	}
}
func TestClassicFixtureFromLibrary(t *testing.T) {
	id, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "id")
	os.WriteFile(path, []byte(id.String()), 0600)
	textRoundTrip(t, id.Recipient().String(), []string{path}, testConnection(""))
}

func TestTagRecipientUsesAutomaticModeWithoutClaimingX25519(t *testing.T) {
	curve := elliptic.P256()
	recipient, err := tag.NewClassicRecipient(elliptic.MarshalCompressed(curve, curve.Params().Gx, curve.Params().Gy))
	if err != nil {
		t.Fatal(err)
	}
	plain := "public synthetic tag fixture"
	r := request{Operation: "encrypt", Text: &plain, Protection: "classic", Recipients: recipient.String()}
	if _, err = execute(r, testConnection("")); err == nil {
		t.Fatal("P-256 tag was misrepresented as X25519")
	}
	r.Protection = "auto"
	if _, err = execute(r, testConnection("")); err != nil {
		t.Fatal(err)
	}
}
