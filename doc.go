// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-ruby-hiera-eyaml/hiera-eyaml authors

// Package hieraeyaml is a pure-Go (no cgo) adapter mirroring the Ruby
// hiera-eyaml gem: it reads eyaml YAML data, decrypts the ENC[...] scalars it
// contains, and exposes an "eyaml" data_hash backend for the
// github.com/go-hiera/hiera engine.
//
// The cryptography lives entirely in github.com/go-eyaml/eyaml; this package is
// the thin, hiera-facing layer on top of it:
//
//   - a [Config]/[New] pair that builds a [Backend] from pkcs7 PEM material
//     and/or gpg OpenPGP keyrings, supplied either inline
//     (PublicKeyPEM/PrivateKeyPEM, GPGPublicKeyRing/GPGPrivateKeyRing) or by
//     path through an injectable [FS] seam so callers and tests never need real
//     files;
//   - [Backend.EncryptString] / [Backend.DecryptString] for single scalars
//     ([Backend.EncryptStringWith] selects the scheme; DecryptString dispatches
//     on the token's scheme), and [Backend.DecryptValue] to walk a decoded
//     value tree decrypting every ENC[...] token it finds (block and inline
//     string forms alike);
//   - [Backend.DataHash], a func(data []byte, path string) (map[string]any,
//     error) that YAML-parses a data file and decrypts it, matching the
//     signature go-hiera's Hiera.RegisterDataHash expects;
//   - [Backend.Register], which registers DataHash under the name "eyaml" on a
//     *hiera.Hiera so a hierarchy level can select "data_hash: eyaml".
//
// Both hiera-eyaml encryptors are supported, inherited from go-eyaml: pkcs7
// (ENC[PKCS7,...]) and gpg (ENC[GPG,...]). A single data file may mix them;
// DataHash decrypts each scalar with the encryptor its token names.
package hieraeyaml
