package protocol_test

import (
	"testing"
	"time"

	"github.com/purpleproto/core/pkg/config"
	"github.com/purpleproto/core/pkg/domain"
	"github.com/purpleproto/core/pkg/handshake"
	"github.com/purpleproto/core/pkg/protocol"
	"github.com/purpleproto/core/pkg/strategy"
)

func TestCoreSealAndOpenRoundTrip(t *testing.T) {
	cfg := config.Default("super-secret-password")
	core, err := protocol.New(cfg, strategy.Noise{Padding: 32})
	if err != nil {
		t.Fatalf("protocol.New() error = %v", err)
	}

	salt := []byte("abcd0123456789")
	payload := []byte("wassup!")
	aad := []byte("meta")

	frame, err := core.Seal(salt, payload, aad)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	if len(frame.Padding) != 32 {
		t.Fatalf("expected padding length 32, got %d", len(frame.Padding))
	}

	plaintext, err := core.Open(salt, frame, aad)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if string(plaintext) != string(payload) {
		t.Fatalf("plaintext mismatch: got %q want %q", plaintext, payload)
	}
}

func TestHandshakeServiceInspect(t *testing.T) {
	cfg := config.Default("super-secret-pass")
	service, err := handshake.NewService(cfg)
	if err != nil {
		t.Fatalf("NewService() error %v", err)
	}

	now := time.Unix(1_710_000_000, 0).UTC()
	validHeader := service.ComputeHeader(now)
	result := service.Inspect(domain.HandshakeAttempt{
		ObservedAt: now,
		Header:     validHeader,
	})

	if result.Mode != domain.ModeTunnel {
		t.Fatalf("expected tunnel mode, got %s", result.Mode)
	}

	invalid := service.Inspect(domain.HandshakeAttempt{
		ObservedAt: now,
		Header:     []byte("yepyepyepyepyep! ")[:16],
	})

	if invalid.Mode != domain.ModeFallback {
		t.Fatalf("expected fallback mode, got %s", invalid.Mode)
	}

	if len(invalid.Response) == 0 {
		t.Fatalf("expected fallback response")
	}
}
