// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-ruby-hiera-eyaml/hiera-eyaml authors

package hieraeyaml

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/go-eyaml/eyaml"
	gohiera "github.com/go-hiera/hiera"
	"github.com/go-ruby-yaml/yaml"
)

// --- shared test key material ---

var (
	keysOnce sync.Once
	certPEM  []byte
	keyPEM   []byte
)

func material(t *testing.T) (cert, key []byte) {
	t.Helper()
	keysOnce.Do(func() {
		kp, err := eyaml.CreateKeys(&eyaml.KeyOptions{Bits: 1024})
		if err != nil {
			panic(err)
		}
		certPEM, keyPEM = kp.PublicKeyPEM, kp.PrivateKeyPEM
	})
	return certPEM, keyPEM
}

func backend(t *testing.T) *Backend {
	t.Helper()
	c, k := material(t)
	b, err := New(Config{PublicKeyPEM: c, PrivateKeyPEM: k})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// encTok encrypts s and returns its ENC[PKCS7,...] token.
func encTok(t *testing.T, b *Backend, s string) string {
	t.Helper()
	tok, err := b.EncryptString(s)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// memFS is an in-memory FS seam.
type memFS struct {
	files map[string][]byte
	err   error
}

func (m memFS) ReadFile(name string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	b, ok := m.files[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

// --- New ---

func TestNewInlineBoth(t *testing.T) {
	c, k := material(t)
	b, err := New(Config{PublicKeyPEM: c, PrivateKeyPEM: k})
	if err != nil || b == nil {
		t.Fatalf("err=%v b=%v", err, b)
	}
}

func TestNewViaPathFS(t *testing.T) {
	c, k := material(t)
	fs := memFS{files: map[string][]byte{"cert.pem": c, "key.pem": k}}
	b, err := New(Config{PublicKeyPath: "cert.pem", PrivateKeyPath: "key.pem", FS: fs})
	if err != nil || b == nil {
		t.Fatalf("err=%v", err)
	}
}

func TestNewDefaultOSFS(t *testing.T) {
	c, k := material(t)
	dir := t.TempDir()
	cp := filepath.Join(dir, "cert.pem")
	kp := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cp, c, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, k, 0o600); err != nil {
		t.Fatal(err)
	}
	// FS nil => default osFS is used to read the real files.
	b, err := New(Config{PublicKeyPath: cp, PrivateKeyPath: kp})
	if err != nil || b == nil {
		t.Fatalf("err=%v", err)
	}
}

func TestNewPathReadErrors(t *testing.T) {
	c, _ := material(t)
	boom := errors.New("read boom")
	// certificate path read error
	if _, err := New(Config{PublicKeyPath: "cert.pem", FS: memFS{err: boom}}); !errors.Is(err, boom) {
		t.Fatalf("cert read err = %v", err)
	}
	// private-key path read error (cert supplied inline so we reach the key read)
	if _, err := New(Config{PublicKeyPEM: c, PrivateKeyPath: "key.pem", FS: memFS{err: boom}}); !errors.Is(err, boom) {
		t.Fatalf("key read err = %v", err)
	}
}

func TestNewNoMaterial(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("want no-material error")
	}
}

func TestNewBadPEM(t *testing.T) {
	if _, err := New(Config{PublicKeyPEM: []byte("not pem")}); err == nil {
		t.Error("want bad-cert error")
	}
	c, _ := material(t)
	if _, err := New(Config{PublicKeyPEM: c, PrivateKeyPEM: []byte("not pem")}); err == nil {
		t.Error("want bad-key error")
	}
}

// --- Encrypt / Decrypt string ---

func TestEncryptDecryptString(t *testing.T) {
	b := backend(t)
	tok := encTok(t, b, "swordfish")
	if !eyaml.IsToken(tok) {
		t.Fatalf("not a token: %q", tok)
	}
	got, err := b.DecryptString(tok)
	if err != nil || got != "swordfish" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestDecryptStringPassthrough(t *testing.T) {
	b := backend(t)
	got, err := b.DecryptString("plain text")
	if err != nil || got != "plain text" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestDecryptStringError(t *testing.T) {
	b := backend(t)
	// Well-formed token, but the payload is not a valid PKCS7 structure.
	if _, err := b.DecryptString("ENC[PKCS7,AAAA]"); err == nil {
		t.Error("want decrypt error")
	}
}

// --- DecryptValue ---

func TestDecryptValueTree(t *testing.T) {
	b := backend(t)
	tree := map[string]any{
		"user":     "alice",
		"password": encTok(t, b, "s3cr3t"),
		"nested": map[string]any{
			"api_key": encTok(t, b, "key-123"),
		},
		"list":   []any{"plain", encTok(t, b, "enc-item")},
		"number": 42,
	}
	out, err := b.DecryptValue(tree)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["password"] != "s3cr3t" {
		t.Errorf("password = %v", m["password"])
	}
	if m["nested"].(map[string]any)["api_key"] != "key-123" {
		t.Errorf("api_key = %v", m["nested"])
	}
	if m["list"].([]any)[1] != "enc-item" {
		t.Errorf("list = %v", m["list"])
	}
	if m["number"] != 42 {
		t.Errorf("number = %v", m["number"])
	}
}

func TestDecryptValueErrors(t *testing.T) {
	b := backend(t)
	bad := "ENC[PKCS7,AAAA]"
	// error inside a map value
	if _, err := b.DecryptValue(map[string]any{"k": bad}); err == nil {
		t.Error("want map error")
	}
	// error inside a slice element
	if _, err := b.DecryptValue([]any{bad}); err == nil {
		t.Error("want slice error")
	}
	// error on a top-level string
	if _, err := b.DecryptValue(bad); err == nil {
		t.Error("want string error")
	}
}

// --- DataHash ---

func TestDataHashEmpty(t *testing.T) {
	b := backend(t)
	m, err := b.DataHash([]byte("   \n"), "empty.eyaml")
	if err != nil || len(m) != 0 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestDataHashYAMLError(t *testing.T) {
	b := backend(t)
	// A tab used for indentation is a hard YAML syntax error.
	if _, err := b.DataHash([]byte("a:\n\t- x\n"), "bad.eyaml"); err == nil {
		t.Error("want yaml error")
	}
}

func TestDataHashNotMapping(t *testing.T) {
	b := backend(t)
	if _, err := b.DataHash([]byte("- one\n- two\n"), "list.eyaml"); err == nil {
		t.Error("want non-mapping error")
	}
}

func TestDataHashDecryptError(t *testing.T) {
	b := backend(t)
	if _, err := b.DataHash([]byte("secret: ENC[PKCS7,AAAA]\n"), "bad.eyaml"); err == nil {
		t.Error("want decrypt error")
	}
}

func TestDataHashMixed(t *testing.T) {
	b := backend(t)
	inline := encTok(t, b, "inline-secret")
	block := encTok(t, b, "block-secret")
	doc := "plain: hello\n" +
		"password: " + inline + "\n" +
		"multiline: >\n" +
		"    " + block + "\n"
	m, err := b.DataHash([]byte(doc), "app.eyaml")
	if err != nil {
		t.Fatal(err)
	}
	if m["plain"] != "hello" {
		t.Errorf("plain = %v", m["plain"])
	}
	if m["password"] != "inline-secret" {
		t.Errorf("password = %v", m["password"])
	}
	if m["multiline"] != "block-secret" {
		t.Errorf("multiline = %v (%T)", m["multiline"], m["multiline"])
	}
}

// --- normalize / keyString / topHash white-box ---

func TestNormalizePlainMapBranch(t *testing.T) {
	// Load never yields a plain map[string]any; hit that branch directly.
	in := map[string]any{"a": []any{yaml.Symbol("sym"), 7}}
	out := normalize(in).(map[string]any)
	if out["a"].([]any)[0] != "sym" || out["a"].([]any)[1] != 7 {
		t.Fatalf("normalize plain map = %v", out)
	}
}

func TestNormalizeYAMLMapAndKeyString(t *testing.T) {
	m := yaml.NewMap()
	m.Set("str", "v")
	m.Set(yaml.Symbol("sym"), "w")
	m.Set(123, "x") // non-string, non-symbol key => keyString default branch
	out := normalize(m).(map[string]any)
	if out["str"] != "v" || out["sym"] != "w" || out["123"] != "x" {
		t.Fatalf("normalize *Map = %v", out)
	}
}

func TestTopHashNil(t *testing.T) {
	m, err := topHash(nil, "p")
	if err != nil || len(m) != 0 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

// --- end-to-end through the go-hiera engine ---

func TestRegisterAndLookup(t *testing.T) {
	b := backend(t)
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := encTok(t, b, "top-secret")
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
		t.Fatalf("lookup secret: found=%v err=%v", found, err)
	}
	if v != "top-secret" {
		t.Fatalf("decrypted lookup = %v", v)
	}

	v, found, err = h.Lookup("plain_key", nil)
	if err != nil || !found || v != "plain_value" {
		t.Fatalf("lookup plain: v=%v found=%v err=%v", v, found, err)
	}
}
