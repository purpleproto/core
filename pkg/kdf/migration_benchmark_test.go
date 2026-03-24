package kdf_test

import (
	"testing"

	"github.com/purpleproto/core/pkg/kdf"
	"github.com/purpleproto/core/pkg/kdf/argon2id"
	legacy "github.com/purpleproto/core/pkg/kdf/pbkdf2"
)

func BenchmarkPBKDF2Provider(b *testing.B) {
	p := legacy.Provider{Iterations: 120000}
	salt := []byte("benchmark-salt")

	for b.Loop() {
		p.Derive("benchmark-pass", salt, 32)
	}
}

func BenchmarkArgon2IDProvider(b *testing.B) {
	p := argon2id.Provider{
		Time:    2,
		Memory:  4 * 1024,
		Threads: 1,
	}
	salt := []byte("benchmark-salt")

	for b.Loop() {
		p.Derive("benchmark-pass", salt, 32)
	}
}

func BenchmarkMigrationProvider(b *testing.B) {
	p := kdf.MigrationProvider{
		Preferred: argon2id.Provider{
			Time:    2,
			Memory:  4 * 1024,
			Threads: 1,
		},
		Legacy: legacy.Provider{Iterations: 120000},
	}
	salt := []byte("benchmark-salt")

	for b.Loop() {
		p.Derive("benchmark-pass", salt, 32)
	}
}
