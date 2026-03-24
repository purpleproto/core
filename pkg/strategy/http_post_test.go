package strategy

import (
	"bytes"
	"testing"

	"github.com/purpleproto/core/pkg/domain"
)

func TestHTTPPostWrapAndDeserialize(t *testing.T) {
	strat := HTTPPost{
		Host:      "test.example.org",
		Path:      "/get",
		UserAgent: "curl/1.2.3",
	}

	in := domain.Frame{
		Nonce:      []byte("nonce"),
		Ciphertext: []byte("cipher"),
		Padding:    []byte("pad"),
	}

	out, err := strat.Wrap(in)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	if !bytes.Contains(out.Ciphertext, []byte("POST /get HTTP/1.1")) {
		t.Fatalf("expected wrapped request line")
	}

	decoded, err := DesearializeHTTPPostFrame(out.Ciphertext)
	if err != nil {
		t.Fatalf("DesearializeHTTPPostFrame() error = %v", err)
	}

	if !bytes.Equal(decoded.Nonce, in.Nonce) ||
		!bytes.Equal(decoded.Ciphertext, in.Ciphertext) ||
		!bytes.Equal(decoded.Padding, in.Padding) {
		t.Fatalf("decoded frame mismatch")
	}
}
