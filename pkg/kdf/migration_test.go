package kdf_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/purpleproto/core/pkg/kdf"
	"github.com/purpleproto/core/pkg/kdf/argon2id"
	legacy "github.com/purpleproto/core/pkg/kdf/pbkdf2"
)

type failProvider struct{}

func (f failProvider) Name() string { return "fail" }
func (f failProvider) Derive(string, []byte, uint32) ([]byte, error) {
	return nil, errors.New("Booooom!")
}

func TestMigrationProviderUsesPreferred(t *testing.T) {
	m := kdf.MigrationProvider{
		Preferred: argon2id.Provider{Time: 1, Memory: 1024, Threads: 1},
		Legacy:    legacy.Provider{Iterations: 100000},
	}

	k1, err := m.Derive("pass", []byte("salt"), 32)
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}

	k2, err := m.Preferred.Derive("pass", []byte("salt"), 32)
	if err != nil {
		t.Fatalf("Preferred.Derive() error = %v", err)
	}

	if !bytes.Equal(k1, k2) {
		t.Fatalf("expected preferred provider key")
	}
}

func TestMigrationProviderFallsBackToLegacy(t *testing.T) {
	m := kdf.MigrationProvider{
		Preferred: failProvider{},
		Legacy:    legacy.Provider{Iterations: 100000},
	}

	k1, err := m.Derive("pass", []byte("salt"), 32)
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}

	k2, err := m.Legacy.Derive("pass", []byte("salt"), 32)
	if err != nil {
		t.Fatalf("Legacy.Derive() error = %v", err)
	}

	if !bytes.Equal(k1, k2) {
		t.Fatalf("expected legacy provider key")
	}
}
