package kdf

import (
	"fmt"
)

type MigrationProvider struct {
	Preferred Provider
	Legacy    Provider
}

func (m MigrationProvider) Name() string {
	if m.Preferred != nil {
		return m.Preferred.Name()
	}

	if m.Legacy != nil {
		return m.Legacy.Name()
	}

	return ""
}

func (m MigrationProvider) Derive(password string, salt []byte, keyLen uint32) ([]byte, error) {
	if m.Preferred != nil {
		key, err := m.Preferred.Derive(password, salt, keyLen)
		if err == nil {
			return key, nil
		}
	}

	if m.Legacy != nil {
		return m.Legacy.Derive(password, salt, keyLen)
	}

	return nil, fmt.Errorf("derive session key: %w", ErrUnknownProvider)
}
