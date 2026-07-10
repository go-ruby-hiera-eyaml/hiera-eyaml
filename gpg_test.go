// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-ruby-hiera-eyaml/hiera-eyaml authors

package hieraeyaml

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gohiera "github.com/go-hiera/hiera"
)

// --- shared GPG test key material (generated once, small key for speed) ---

var (
	gpgOnce sync.Once
	gpgPub  []byte
	gpgPriv []byte
)

// gpgMaterial returns a throwaway OpenPGP public and secret keyring (binary).
func gpgMaterial(t *testing.T) (pub, priv []byte) {
	t.Helper()
	gpgOnce.Do(func() {
		e, err := openpgp.NewEntity("hiera-eyaml test", "gpg", "gpg@example.com", &packet.Config{RSABits: 1024})
		if err != nil {
			panic(err)
		}
		var pb, pv bytes.Buffer
		if err := e.Serialize(&pb); err != nil {
			panic(err)
		}
		if err := e.SerializePrivate(&pv, nil); err != nil {
			panic(err)
		}
		gpgPub, gpgPriv = pb.Bytes(), pv.Bytes()
	})
	return gpgPub, gpgPriv
}

// gpgBackend is a GPG-only backend (round-trip capable).
func gpgBackend(t *testing.T) *Backend {
	t.Helper()
	pub, priv := gpgMaterial(t)
	b, err := New(Config{GPGPublicKeyRing: pub, GPGPrivateKeyRing: priv})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bothBackend supports both schemes (pkcs7 default, gpg secondary).
func bothBackend(t *testing.T) *Backend {
	t.Helper()
	c, k := material(t)
	pub, priv := gpgMaterial(t)
	b, err := New(Config{
		PublicKeyPEM: c, PrivateKeyPEM: k,
		GPGPublicKeyRing: pub, GPGPrivateKeyRing: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- New (gpg) ---

func TestNewGPGInline(t *testing.T) {
	b := gpgBackend(t)
	tok, err := b.EncryptString("gpg-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "ENC[GPG,") {
		t.Fatalf("default scheme not gpg: %q", tok)
	}
	got, err := b.DecryptString(tok)
	if err != nil || got != "gpg-secret" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestNewGPGViaPath(t *testing.T) {
	pub, priv := gpgMaterial(t)
	fs := memFS{files: map[string][]byte{"pub.gpg": pub, "priv.gpg": priv}}
	b, err := New(Config{GPGPublicKeyRingPath: "pub.gpg", GPGPrivateKeyRingPath: "priv.gpg", FS: fs})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := b.EncryptStringWith("GPG", "via-path")
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.DecryptString(tok)
	if err != nil || got != "via-path" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestNewGPGPathReadErrors(t *testing.T) {
	pub, _ := gpgMaterial(t)
	boom := errors.New("read boom")
	// public keyring path read error
	if _, err := New(Config{GPGPublicKeyRingPath: "pub.gpg", FS: memFS{err: boom}}); !errors.Is(err, boom) {
		t.Fatalf("gpg pub read err = %v", err)
	}
	// private keyring path read error (pub supplied inline so we reach the priv read)
	if _, err := New(Config{GPGPublicKeyRing: pub, GPGPrivateKeyRingPath: "priv.gpg", FS: memFS{err: boom}}); !errors.Is(err, boom) {
		t.Fatalf("gpg priv read err = %v", err)
	}
}

func TestNewGPGBadKeyring(t *testing.T) {
	if _, err := New(Config{GPGPublicKeyRing: []byte("not a keyring")}); err == nil {
		t.Error("want bad-keyring error")
	}
}

// --- EncryptStringWith ---

func TestEncryptStringWith(t *testing.T) {
	b := bothBackend(t)
	p7, err := b.EncryptStringWith("PKCS7", "via-pkcs7")
	if err != nil || !strings.HasPrefix(p7, "ENC[PKCS7,") {
		t.Fatalf("pkcs7 tok=%q err=%v", p7, err)
	}
	gpg, err := b.EncryptStringWith("GPG", "via-gpg")
	if err != nil || !strings.HasPrefix(gpg, "ENC[GPG,") {
		t.Fatalf("gpg tok=%q err=%v", gpg, err)
	}
	// Each decrypts back through scheme dispatch.
	if got, _ := b.DecryptString(p7); got != "via-pkcs7" {
		t.Errorf("pkcs7 rt = %q", got)
	}
	if got, _ := b.DecryptString(gpg); got != "via-gpg" {
		t.Errorf("gpg rt = %q", got)
	}
}

func TestEncryptStringWithUnknownScheme(t *testing.T) {
	b := backend(t) // pkcs7 only
	if _, err := b.EncryptStringWith("GPG", "x"); err == nil {
		t.Error("want unknown-scheme error")
	}
}

// --- DecryptString dispatch ---

func TestDecryptStringSchemeNotConfigured(t *testing.T) {
	// A pkcs7-only backend cannot decrypt a GPG token.
	b := backend(t)
	gb := gpgBackend(t)
	gpgTok, err := gb.EncryptString("only-gpg-can-open")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.DecryptString(gpgTok); err == nil {
		t.Error("want scheme-not-configured error")
	}
}

func TestDecryptStringParseError(t *testing.T) {
	b := backend(t)
	// IsToken matches the permissive payload alphabet, but the payload is not
	// valid base64, so ParseToken fails before scheme dispatch.
	if _, err := b.DecryptString("ENC[PKCS7,@@@notbase64@@@]"); err == nil {
		t.Error("want parse error")
	}
}

// --- DataHash with mixed schemes ---

func TestDataHashMixedSchemes(t *testing.T) {
	b := bothBackend(t)
	p7, err := b.EncryptStringWith("PKCS7", "pkcs7-secret")
	if err != nil {
		t.Fatal(err)
	}
	gpg, err := b.EncryptStringWith("GPG", "gpg-secret")
	if err != nil {
		t.Fatal(err)
	}
	doc := "plain: hello\n" +
		"p7_password: " + p7 + "\n" +
		"gpg_password: " + gpg + "\n"
	m, err := b.DataHash([]byte(doc), "mixed.eyaml")
	if err != nil {
		t.Fatal(err)
	}
	if m["plain"] != "hello" {
		t.Errorf("plain = %v", m["plain"])
	}
	if m["p7_password"] != "pkcs7-secret" {
		t.Errorf("p7_password = %v", m["p7_password"])
	}
	if m["gpg_password"] != "gpg-secret" {
		t.Errorf("gpg_password = %v", m["gpg_password"])
	}
}

// --- end-to-end through go-hiera with a GPG-encrypted value ---

func TestRegisterAndLookupGPG(t *testing.T) {
	b := gpgBackend(t)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret, err := b.EncryptString("gpg-top-secret")
	if err != nil {
		t.Fatal(err)
	}
	common := "plain_key: plain_value\n" + "secret_key: " + secret + "\n"
	if err := os.WriteFile(filepath.Join(dataDir, "common.yaml"), []byte(common), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "" +
		"version: 5\n" +
		"defaults:\n" +
		"  datadir: data\n" +
		"  data_hash: eyaml\n" +
		"hierarchy:\n" +
		"  - name: Common\n" +
		"    path: common.yaml\n"
	cfgPath := filepath.Join(dir, "hiera.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	h, err := gohiera.Load(cfgPath, gohiera.MapScope{})
	if err != nil {
		t.Fatal(err)
	}
	b.Register(h)

	v, found, err := h.Lookup("secret_key", nil)
	if err != nil || !found {
		t.Fatalf("lookup gpg secret: found=%v err=%v", found, err)
	}
	if v != "gpg-top-secret" {
		t.Fatalf("decrypted gpg lookup = %v", v)
	}
}
