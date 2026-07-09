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

// Config configures a [Backend]. Key material is the RSA private key and the
// matching X.509 certificate (hiera-eyaml's "public key"). Supply either the
// inline PEM fields or the *Path fields; inline PEM wins when both are set.
// Provide only the certificate for an encrypt-only backend, only the private
// key for a decrypt-only backend, or both for round trips.
type Config struct {
	// PublicKeyPEM / PrivateKeyPEM are inline PEM blocks.
	PublicKeyPEM  []byte
	PrivateKeyPEM []byte
	// PublicKeyPath / PrivateKeyPath are read through FS when the matching
	// inline field is empty.
	PublicKeyPath  string
	PrivateKeyPath string
	// FS overrides the file-access seam (defaults to the OS filesystem).
	FS FS
}

// Backend decrypts and encrypts eyaml data. Construct one with [New].
type Backend struct {
	enc *eyaml.PKCS7
}

// New builds a [Backend] from cfg. It errors if a configured path cannot be
// read, if the PEM material is invalid, or if no key material is supplied at
// all.
func New(cfg Config) (*Backend, error) {
	fsys := cfg.FS
	if fsys == nil {
		fsys = osFS{}
	}
	certPEM := cfg.PublicKeyPEM
	if len(certPEM) == 0 && cfg.PublicKeyPath != "" {
		b, err := fsys.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("hiera-eyaml: read certificate: %w", err)
		}
		certPEM = b
	}
	keyPEM := cfg.PrivateKeyPEM
	if len(keyPEM) == 0 && cfg.PrivateKeyPath != "" {
		b, err := fsys.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("hiera-eyaml: read private key: %w", err)
		}
		keyPEM = b
	}
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return nil, errors.New("hiera-eyaml: no key material configured")
	}
	p, err := eyaml.NewPKCS7(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &Backend{enc: p}, nil
}

// EncryptString seals s into an ENC[PKCS7,...] token.
func (b *Backend) EncryptString(s string) (string, error) {
	return eyaml.Encrypt(b.enc, []byte(s))
}

// DecryptString decrypts s when it is an ENC[...] token and returns it verbatim
// otherwise, so plaintext scalars pass through unchanged.
func (b *Backend) DecryptString(s string) (string, error) {
	if !eyaml.IsToken(s) {
		return s, nil
	}
	pt, err := eyaml.Decrypt(b.enc, s)
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
