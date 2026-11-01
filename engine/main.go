// age-engine is a narrow, local stdio adapter for the official age library.
// It does not accept shell commands, start a server, or implement cryptography.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/plugin"
)

const protocol = 1
const ageVersion = "1.3.2"
const textLimit = 1 << 20

type request struct {
	Protocol       int      `json:"protocol"`
	Operation      string   `json:"operation"`
	Input          string   `json:"input,omitempty"`
	Output         string   `json:"output,omitempty"` // pre-created, private staging file owned by the Rust parent
	Text           *string  `json:"text,omitempty"`
	Protection     string   `json:"protection,omitempty"`
	Recipients     string   `json:"recipients,omitempty"`
	RecipientFiles []string `json:"recipient_files,omitempty"`
	IdentityFiles  []string `json:"identity_files,omitempty"`
	IdentityText   string   `json:"identity_text,omitempty"`
	Plugins        []string `json:"plugins,omitempty"`
	PluginDir      string   `json:"plugin_dir,omitempty"`
	Passphrase     string   `json:"passphrase,omitempty"`
	Armor          bool     `json:"armor,omitempty"`
	KeyKind        string   `json:"key_kind,omitempty"`
	ProtectKey     bool     `json:"protect_key,omitempty"`
}

type response struct {
	Type       string          `json:"type"`
	Bytes      int64           `json:"bytes,omitempty"`
	Message    string          `json:"message,omitempty"`
	PromptID   uint64          `json:"prompt_id,omitempty"`
	Secret     bool            `json:"secret,omitempty"`
	Yes        string          `json:"yes,omitempty"`
	No         string          `json:"no,omitempty"`
	PublicKeys []string        `json:"public_keys,omitempty"`
	Text       *string         `json:"text,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	Engine     string          `json:"engine,omitempty"`
	Go         string          `json:"go,omitempty"`
}
type answer struct {
	PromptID uint64 `json:"prompt_id"`
	Value    string `json:"value"`
	Cancel   bool   `json:"cancel"`
}

type connection struct {
	input  *bufio.Scanner
	output *json.Encoder
	mu     sync.Mutex
	nextID uint64
}

func (c *connection) send(r response) { c.mu.Lock(); defer c.mu.Unlock(); _ = c.output.Encode(r) }
func (c *connection) ask(message string, secret bool, yes, no string) (string, error) {
	c.nextID++
	id := c.nextID
	c.send(response{Type: "prompt", PromptID: id, Message: message, Secret: secret, Yes: yes, No: no})
	if !c.input.Scan() {
		return "", errors.New("request cancelled")
	}
	var a answer
	if err := json.Unmarshal(c.input.Bytes(), &a); err != nil || a.PromptID != id || a.Cancel {
		return "", errors.New("request cancelled")
	}
	return a.Value, nil
}
func (c *connection) ui() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			c.send(response{Type: "status", Message: name + ": " + message})
			return nil
		},
		RequestValue: func(name, message string, secret bool) (string, error) {
			return c.ask(name+": "+message, secret, "", "")
		},
		Confirm: func(name, message, yes, no string) (bool, error) {
			v, err := c.ask(name+": "+message, false, yes, no)
			return v == "yes", err
		},
		WaitTimer: func(name string) {
			c.send(response{Type: "status", Message: "Waiting for " + name + ". Your hardware token may need a touch."})
		},
	}
}

func main() {
	// age's debug plugin transcript contains secret protocol material. Never
	// inherit that diagnostic switch into a GUI operation.
	_ = os.Unsetenv("AGEDEBUG")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 16<<20)
	c := &connection{input: scanner, output: json.NewEncoder(os.Stdout)}
	if !scanner.Scan() {
		return
	}
	var r request
	if err := json.Unmarshal(scanner.Bytes(), &r); err != nil || r.Protocol != protocol {
		c.send(response{Type: "error", Message: "Unsupported engine request."})
		return
	}
	// Plugin lookups match age's PATH convention. The additional location is
	// explicitly selected by the user; ciphertext never determines a plugin.
	if r.PluginDir != "" {
		if !filepath.IsAbs(r.PluginDir) {
			c.send(response{Type: "error", Message: "Plugin folder must be an absolute path."})
			return
		}
		_ = os.Setenv("PATH", r.PluginDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	if executable, err := os.Executable(); err == nil {
		_ = os.Setenv("PATH", filepath.Dir(executable)+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	result, err := execute(r, c)
	r.Passphrase = ""
	r.IdentityText = ""
	if err != nil {
		c.send(response{Type: "error", Message: err.Error()})
		return
	}
	result.Type = "result"
	c.send(result)
}

func execute(r request, c *connection) (response, error) {
	switch r.Operation {
	case "version":
		return response{Engine: "age " + ageVersion + " / desktop bridge 0.2.0", Go: runtime.Version()}, nil
	case "generate_passphrase":
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return response{}, err
		}
		value := base64.RawURLEncoding.EncodeToString(b)
		clear(b)
		return response{Text: &value}, nil
	case "generate_key":
		return generateKey(r, c)
	case "public_keys":
		ids, err := loadIdentities(r, c)
		if err != nil {
			return response{}, err
		}
		recs, err := identitiesToRecipients(ids)
		if err != nil {
			return response{}, err
		}
		var public []string
		for _, rec := range recs {
			s, ok := rec.(fmt.Stringer)
			if !ok {
				return response{}, errors.New("This identity cannot be exported as a public recipient")
			}
			public = append(public, s.String())
		}
		if len(public) == 0 {
			return response{}, errors.New("Choose at least one identity")
		}
		return response{PublicKeys: public}, nil
	case "inspect":
		return inspect(r)
	case "encrypt", "decrypt":
		return transform(r, c)
	default:
		return response{}, errors.New("Unknown operation")
	}
}

func inputFor(r request) (io.ReadCloser, error) {
	if r.Text != nil {
		limit := textLimit
		if r.Operation == "decrypt" {
			limit = textLimit * 2
		}
		if len(*r.Text) > limit {
			return nil, errors.New("Text is limited to 1 MiB. Use Files for larger input.")
		}
		return io.NopCloser(strings.NewReader(*r.Text)), nil
	}
	f, err := os.Open(r.Input)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("Input must be a regular file. Archive folders first.")
	}
	return f, nil
}
func stagedOutput(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("Missing staging file")
	}
	// The Rust parent creates this file with owner-only permissions before
	// passing it over stdio. Never create or truncate an arbitrary destination.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != 0 {
		f.Close()
		return nil, errors.New("Output staging file must be an empty regular file")
	}
	return f, nil
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("Text output is too large. Use Files instead.")
	}
	return b.Buffer.Write(p)
}

type progressWriter struct {
	w     io.Writer
	c     *connection
	bytes int64
	last  time.Time
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.bytes += int64(n)
	if time.Since(w.last) > 100*time.Millisecond {
		w.c.send(response{Type: "progress", Bytes: w.bytes})
		w.last = time.Now()
	}
	return n, err
}

func transform(r request, c *connection) (response, error) {
	in, err := inputFor(r)
	if err != nil {
		return response{}, err
	}
	defer in.Close()
	var out io.Writer
	var file *os.File
	memory := &limitedBuffer{limit: textLimit * 2}
	if r.Operation == "decrypt" {
		memory.limit = textLimit
	}
	if r.Text != nil {
		out = memory
	} else {
		file, err = stagedOutput(r.Output)
		if err != nil {
			return response{}, err
		}
		defer file.Close()
		out = file
	}
	buffer := make([]byte, 64*1024)
	defer clear(buffer)
	if r.Operation == "encrypt" {
		var recs []age.Recipient
		if r.Protection == "passphrase" {
			if r.Recipients != "" || len(r.RecipientFiles) > 0 || len(r.IdentityFiles) > 0 || len(r.Plugins) > 0 || r.IdentityText != "" {
				return response{}, errors.New("Passphrase encryption cannot be combined with recipients or identities")
			}
			if r.Passphrase == "" {
				return response{}, errors.New("Enter or generate a passphrase")
			}
			rec, err := age.NewScryptRecipient(r.Passphrase)
			if err != nil {
				return response{}, err
			}
			recs = []age.Recipient{rec}
		} else {
			recs, err = loadRecipients(r, c)
			if err != nil {
				return response{}, err
			}
			ids, e := loadIdentities(r, c)
			if e != nil {
				return response{}, e
			}
			extra, e := identitiesToRecipients(ids)
			if e != nil {
				return response{}, e
			}
			recs = append(recs, extra...)
			if len(recs) == 0 {
				return response{}, errors.New("Add a recipient, recipient file, identity, or plugin")
			}
			if len(recs) > 1024 {
				return response{}, errors.New("A file may have at most 1024 recipients")
			}
			for _, rec := range recs {
				if err = checkProtection(r.Protection, rec); err != nil {
					return response{}, err
				}
			}
		}
		var armored io.WriteCloser
		if r.Armor || r.Text != nil {
			armored = armor.NewWriter(out)
			out = armored
		}
		writer, err := age.Encrypt(out, recs...)
		if err != nil {
			return response{}, fmt.Errorf("Cannot combine these recipients: %w", err)
		}
		progress := &progressWriter{w: writer, c: c}
		if _, err = io.CopyBuffer(progress, in, buffer); err != nil {
			return response{}, err
		}
		if err = writer.Close(); err != nil {
			return response{}, err
		}
		if armored != nil {
			if err = armored.Close(); err != nil {
				return response{}, err
			}
		}
	} else {
		ids, e := loadIdentities(r, c)
		if e != nil {
			return response{}, e
		}
		// Auto-detection keeps the interface usable for a mixed batch. This
		// intentional GUI convenience is documented alongside CLI flag parity.
		ids = append([]age.Identity{&lazyScrypt{passphrase: func() (string, error) {
			if r.Passphrase != "" {
				return r.Passphrase, nil
			}
			return c.ask("Passphrase for this encrypted file", true, "", "")
		}}}, ids...)
		reader, err := age.Decrypt(unarmor(in), ids...)
		if err != nil {
			return response{}, fmt.Errorf("Unable to unlock file: %w", err)
		}
		progress := &progressWriter{w: out, c: c}
		if _, err = io.CopyBuffer(progress, reader, buffer); err != nil {
			return response{}, fmt.Errorf("File is damaged or incomplete: %w", err)
		}
	}
	if file != nil {
		if err = file.Sync(); err != nil {
			return response{}, err
		}
	}
	if r.Text != nil {
		if !utf8.Valid(memory.Bytes()) {
			return response{}, errors.New("Decrypted data is binary. Use Files to save it without text conversion.")
		}
		value := memory.String()
		return response{Text: &value}, nil
	}
	return response{}, nil
}

func generateKey(r request, c *connection) (response, error) {
	var identity, public string
	switch r.KeyKind {
	case "pq":
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			return response{}, err
		}
		identity = id.String()
		public = id.Recipient().String()
	case "classic", "":
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return response{}, err
		}
		identity = id.String()
		public = id.Recipient().String()
	default:
		return response{}, errors.New("Choose Classic or Post-quantum for native key generation")
	}
	f, err := stagedOutput(r.Output)
	if err != nil {
		return response{}, err
	}
	defer f.Close()
	var out io.Writer = f
	var writer io.WriteCloser
	if r.ProtectKey {
		if r.Passphrase == "" {
			return response{}, errors.New("Enter a passphrase to protect the identity")
		}
		rec, err := age.NewScryptRecipient(r.Passphrase)
		if err != nil {
			return response{}, err
		}
		writer, err = age.Encrypt(f, rec)
		if err != nil {
			return response{}, err
		}
		out = writer
	}
	if _, err = fmt.Fprintf(out, "# created: %s\n# public key: %s\n%s\n", time.Now().Format(time.RFC3339), public, identity); err != nil {
		return response{}, err
	}
	if writer != nil {
		if err = writer.Close(); err != nil {
			return response{}, err
		}
	}
	if err = f.Sync(); err != nil {
		return response{}, err
	}
	return response{PublicKeys: []string{public}}, nil
}

func inspect(r request) (response, error) {
	executable, err := os.Executable()
	if err != nil {
		return response{}, err
	}
	name := "age-inspect"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	command := exec.Command(filepath.Join(filepath.Dir(executable), name), "--json")
	if r.Text != nil {
		command.Stdin = strings.NewReader(*r.Text)
	} else {
		command.Args = append(command.Args, r.Input)
	}
	// This is the official age-inspect executable built from the same module.
	result, err := command.Output()
	if err != nil {
		return response{}, errors.New("Inspection failed. Choose a complete age file; inspection does not decrypt or authenticate it.")
	}
	if !json.Valid(result) {
		return response{}, errors.New("Invalid inspector response")
	}
	return response{Metadata: result}, nil
}

func unarmor(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	prefix, _ := br.Peek(1024 + len(armor.Header))
	if bytes.HasPrefix(bytes.TrimSpace(prefix), []byte(armor.Header)) {
		return armor.NewReader(br)
	}
	return br
}
