package main

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

type encodedRecipient struct {
	age.Recipient
	encoding string
}

func (r *encodedRecipient) String() string { return r.encoding }

type identityWithPublic struct {
	age.Identity
	public age.Recipient
}

func nameSSHIdentity(id age.Identity, recipient age.Recipient, public ssh.PublicKey) []age.Identity {
	return []age.Identity{&identityWithPublic{Identity: id, public: &encodedRecipient{Recipient: recipient, encoding: string(ssh.MarshalAuthorizedKey(public))}}}
}

func sshRawIdentity(raw any) ([]age.Identity, error) {
	public, err := ssh.NewPublicKey(rawPublic(raw))
	if err != nil {
		return nil, err
	}
	switch key := raw.(type) {
	case *rsa.PrivateKey:
		id, err := agessh.NewRSAIdentity(key)
		if err != nil {
			return nil, err
		}
		return nameSSHIdentity(id, id.Recipient(), public), nil
	case *ed25519.PrivateKey:
		id, err := agessh.NewEd25519Identity(*key)
		if err != nil {
			return nil, err
		}
		return nameSSHIdentity(id, id.Recipient(), public), nil
	case ed25519.PrivateKey:
		id, err := agessh.NewEd25519Identity(key)
		if err != nil {
			return nil, err
		}
		return nameSSHIdentity(id, id.Recipient(), public), nil
	default:
		return nil, errors.New("Only RSA and Ed25519 SSH private keys are supported by age")
	}
}

func rawPublic(raw any) any {
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ed25519.PrivateKey:
		return (*k).Public()
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}
