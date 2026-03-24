package strategy

import (
	"bytes"
	"testing"

	"github.com/purpleproto/core/pkg/domain"
)

func TestTLSFakeWrapAndUnwrap(t *testing.T) {
	strat := TLSFake{}
	in := domain.Frame{
		Nonce:      []byte("nonce"),
		Ciphertext: []byte("cipher"),
		Padding:    []byte("pad"),
	}

	out, err := strat.Wrap(in)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	if len(out.Ciphertext) < 5 {
		t.Fatalf("expected tls-like header")
	}

	if out.Ciphertext[0] != 0x17 {
		t.Fatalf("unexpected tls content type: %x", out.Ciphertext[0])
	}

	decoded, err := UnwrapTLSFakeFrame(out.Ciphertext)
	if err != nil {
		t.Fatalf("UnwrapTLSFakeFrame() error = %v", err)
	}

	if !bytes.Equal(decoded.Nonce, in.Nonce) ||
		!bytes.Equal(decoded.Ciphertext, in.Ciphertext) ||
		!bytes.Equal(decoded.Padding, in.Padding) {
		t.Fatalf("decoded frame mismatch")
	}
}
