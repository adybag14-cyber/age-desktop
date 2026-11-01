// A synthetic age plugin for integration testing. Never included in releases.
// It uses official X25519 cryptography; the PIN only exercises the GUI protocol.
package main

import (
	"errors"
	"filippo.io/age"
	"filippo.io/age/plugin"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--recipient" {
		fmt.Println(plugin.EncodeRecipient("desktoptest", []byte{1}))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--identity" {
		fmt.Println(plugin.EncodeIdentity("desktoptest", []byte{1}))
		return
	}
	executable, _ := os.Executable()
	dir := filepath.Dir(executable)
	_ = os.WriteFile(filepath.Join(dir, "plugin.pid"), []byte(strconv.Itoa(os.Getpid())), 0600)
	p, err := plugin.New("desktoptest")
	if err != nil {
		os.Exit(1)
	}
	unlock := func() (*age.X25519Identity, error) {
		_ = p.DisplayMessage("This is the local test plugin, not a hardware token")
		pin, e := p.RequestValue("Test PIN (fixture-pin)", true)
		if e != nil {
			return nil, e
		}
		if pin != "fixture-pin" {
			return nil, errors.New("incorrect test PIN")
		}
		yes, e := p.Confirm("Allow this fixture operation?", "Allow", "Reject")
		if e != nil {
			return nil, e
		}
		if !yes {
			return nil, errors.New("fixture operation declined")
		}
		path := filepath.Join(dir, "fixture.agekey")
		if data, e := os.ReadFile(path); e == nil {
			return age.ParseX25519Identity(strings.TrimSpace(string(data)))
		}
		id, e := age.GenerateX25519Identity()
		if e != nil {
			return nil, e
		}
		if e = os.WriteFile(path, []byte(id.String()), 0600); e != nil {
			return nil, e
		}
		return id, nil
	}
	recipient := func([]byte) (age.Recipient, error) {
		id, e := unlock()
		if e != nil {
			return nil, e
		}
		return id.Recipient(), nil
	}
	p.HandleRecipient(recipient)
	p.HandleIdentityAsRecipient(recipient)
	p.HandleIdentity(func([]byte) (age.Identity, error) { return unlock() })
	os.Exit(p.Main())
}
