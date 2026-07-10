// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-ruby-hiera-eyaml/hiera-eyaml authors

package hieraeyaml

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/go-eyaml/eyaml"
	gohiera "github.com/go-hiera/hiera"
)

// FS is the file-access seam New uses to read PEM material from a path. The
// default is the operating-system filesystem; tests supply an in-memory
// implementation so they need no disk.
type FS interface {
	ReadFile(name string) ([]byte, error)
}

// osFS is the default FS backed by the operating system.
type osFS struct{}

func (osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

// Config configures a [Backend]. It carries key material for either or both of
// hiera-eyaml's encryptors:
//
//   - pkcs7: the RSA private key and matching X.509 certificate (hiera-eyaml's
//     "public key"), via the PublicKey*/PrivateKey* fields;
//   - gpg: OpenPGP recipient and secret keyrings (armored or binary), via the
//     GPG* fields, with an optional GPGPassphrase for a protected secret key.
//
// For each scheme, supply either the inline field or the *Path field; the
// inline value wins when both are set, and *Path fields are read through FS.
// Provide only the public half for an encrypt-only backend, only the secret
// half for a decrypt-only backend, or both for round trips. At least one scheme
// must be configured.
type Config struct {
	// PublicKeyPEM / PrivateKeyPEM are inline pkcs7 PEM blocks.
	PublicKeyPEM  []byte
	PrivateKeyPEM []byte
	// PublicKeyPath / PrivateKeyPath are read through FS when the matching
	// inline pkcs7 field is empty.
	PublicKeyPath  string
	PrivateKeyPath string

	// GPGPublicKeyRing / GPGPrivateKeyRing are inline OpenPGP keyrings
	// (armored or binary).
	GPGPublicKeyRing  []byte
	GPGPrivateKeyRing []byte
	// GPGPublicKeyRingPath / GPGPrivateKeyRingPath are read through FS when
	// the matching inline gpg field is empty.
	GPGPublicKeyRingPath  string
	GPGPrivateKeyRingPath string
	// GPGPassphrase unlocks a passphrase-protected gpg secret key; nil if
	// none.
	GPGPassphrase []byte

	// FS overrides the file-access seam (defaults to the OS filesystem).
	FS FS
}

// Backend decrypts and encrypts eyaml data across the configured schemes.
// Construct one with [New].
type Backend struct {
	// byScheme maps a token scheme label ("PKCS7", "GPG") to its encryptor,
	// so DecryptString can dispatch on the scheme named in each token.
	byScheme map[string]eyaml.Encryptor
	// def is the encryptor EncryptString uses (pkcs7 when configured, else
	// gpg), mirroring hiera-eyaml's default encrypt behaviour.
	def eyaml.Encryptor
}

// resolve returns the inline bytes when present, else reads path through fsys
// (when path is set), else nil.
func resolve(fsys FS, inline []byte, path, what string) ([]byte, error) {
	if len(inline) > 0 {
		return inline, nil
	}
	if path == "" {
		return nil, nil
	}
	b, err := fsys.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hiera-eyaml: read %s: %w", what, err)
	}
	return b, nil
}

// New builds a [Backend] from cfg. It errors if a configured path cannot be
// read, if the key material is invalid, or if no key material is supplied at
// all.
func New(cfg Config) (*Backend, error) {
	fsys := cfg.FS
	if fsys == nil {
		fsys = osFS{}
	}
	b := &Backend{byScheme: map[string]eyaml.Encryptor{}}

	certPEM, err := resolve(fsys, cfg.PublicKeyPEM, cfg.PublicKeyPath, "certificate")
	if err != nil {
		return nil, err
	}
	keyPEM, err := resolve(fsys, cfg.PrivateKeyPEM, cfg.PrivateKeyPath, "private key")
	if err != nil {
		return nil, err
	}
	if len(certPEM) > 0 || len(keyPEM) > 0 {
		p, err := eyaml.NewPKCS7(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		b.byScheme[p.Name()] = p
		b.def = p
	}

	gpgPub, err := resolve(fsys, cfg.GPGPublicKeyRing, cfg.GPGPublicKeyRingPath, "gpg public keyring")
	if err != nil {
		return nil, err
	}
	gpgPriv, err := resolve(fsys, cfg.GPGPrivateKeyRing, cfg.GPGPrivateKeyRingPath, "gpg private keyring")
	if err != nil {
		return nil, err
	}
	if len(gpgPub) > 0 || len(gpgPriv) > 0 {
		g, err := eyaml.NewGPG(gpgPub, gpgPriv, cfg.GPGPassphrase)
		if err != nil {
			return nil, err
		}
		b.byScheme[g.Name()] = g
		if b.def == nil {
			b.def = g
		}
	}

	if b.def == nil {
		return nil, errors.New("hiera-eyaml: no key material configured")
	}
	return b, nil
}

// EncryptString seals s with the default scheme (pkcs7 when configured, else
// gpg) and returns its ENC[...] token.
func (b *Backend) EncryptString(s string) (string, error) {
	return eyaml.Encrypt(b.def, []byte(s))
}

// EncryptStringWith seals s with the named scheme ("PKCS7" or "GPG"), erroring
// when that scheme is not configured.
func (b *Backend) EncryptStringWith(scheme, s string) (string, error) {
	enc, ok := b.byScheme[scheme]
	if !ok {
		return "", fmt.Errorf("hiera-eyaml: scheme %q is not configured", scheme)
	}
	return eyaml.Encrypt(enc, []byte(s))
}

// DecryptString decrypts s when it is an ENC[...] token, dispatching on the
// token's scheme, and returns it verbatim otherwise so plaintext scalars pass
// through unchanged.
func (b *Backend) DecryptString(s string) (string, error) {
	if !eyaml.IsToken(s) {
		return s, nil
	}
	scheme, _, err := eyaml.ParseToken(s)
	if err != nil {
		return "", err
	}
	enc, ok := b.byScheme[scheme]
	if !ok {
		return "", fmt.Errorf("hiera-eyaml: no backend configured for scheme %q", scheme)
	}
	pt, err := eyaml.Decrypt(enc, s)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// DecryptValue walks a decoded value tree (as produced by YAML parsing) and
// decrypts every ENC[...] scalar, leaving other scalars untouched. Maps and
// slices are copied; the input is not mutated.
func (b *Backend) DecryptValue(v any) (any, error) {
	switch x := v.(type) {
	case string:
		return b.DecryptString(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			dv, err := b.DecryptValue(val)
			if err != nil {
				return nil, err
			}
			out[k] = dv
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i := range x {
			dv, err := b.DecryptValue(x[i])
			if err != nil {
				return nil, err
			}
			out[i] = dv
		}
		return out, nil
	default:
		return v, nil
	}
}

// DataHash is the go-hiera data_hash backend seam: it YAML-parses data and
// decrypts every ENC[...] scalar, returning the resulting hash. path is used
// only for error context. Its signature matches the argument
// [gohiera.Hiera.RegisterDataHash] expects.
func (b *Backend) DataHash(data []byte, path string) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	v, err := loadYAML(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m, err := topHash(normalize(v), path)
	if err != nil {
		return nil, err
	}
	dv, err := b.DecryptValue(m)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return dv.(map[string]any), nil
}

// Register installs [Backend.DataHash] as the "eyaml" data_hash backend on h,
// so a hierarchy level may select it with "data_hash: eyaml".
func (b *Backend) Register(h *gohiera.Hiera) {
	h.RegisterDataHash("eyaml", b.DataHash)
}
