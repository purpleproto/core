package strategy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/purpleproto/core/internal/byteutil"
	"github.com/purpleproto/core/pkg/domain"
)

type HTTPPost struct {
	Host      string
	Path      string
	UserAgent string
}

func (h HTTPPost) Name() domain.StrategyName { return domain.StrategyHTTPPost }

func (h HTTPPost) Wrap(frame domain.Frame) (domain.Frame, error) {
	host := h.Host
	if host == "" {
		host = "cdn.example.com"
	}

	path := h.Path
	if path == "" {
		path = "/api/v1/test"
	}

	ua := h.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0"
	}

	body := serializeFrameBody(frame)
	var b bytes.Buffer

	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", ua)
	b.WriteString("Content-Type: application/octet-stream\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("Connection: keep-alive\r\n\r\n")
	b.Write(body)

	frame.Ciphertext = b.Bytes()
	return frame, nil
}

func ParseHTTPPostBody(raw []byte) ([]byte, error) {
	r := bufio.NewReader(bytes.NewReader(raw))
	req, err := http.ReadRequest(r)
	if err != nil {
		return nil, fmt.Errorf("read request: %w", err)
	}

	if req.Method != http.MethodPost {
		return nil, fmt.Errorf("unexpected method: %s", req.Method)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("read request body", err)
	}

	return body, nil
}

func DesearializeHTTPPostFrame(raw []byte) (domain.Frame, error) {
	body, err := ParseHTTPPostBody(raw)
	if err != nil {
		return domain.Frame{}, err
	}
	return deserializeFrameBody(body)
}

func serializeFrameBody(frame domain.Frame) []byte {
	nonceLen := len(frame.Nonce)
	cipherLen := len(frame.Ciphertext)
	padLen := len(frame.Padding)

	var b bytes.Buffer

	b.WriteString(strconv.Itoa(nonceLen))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(cipherLen))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(padLen))
	b.WriteByte('|')

	b.Write(frame.Nonce)
	b.Write(frame.Ciphertext)
	b.Write(frame.Padding)

	return b.Bytes()
}

func deserializeFrameBody(body []byte) (domain.Frame, error) {
	parts := bytes.SplitN(body, []byte("|"), 4)
	if len(parts) != 4 {
		return domain.Frame{}, fmt.Errorf("malformed frame body header")
	}

	nonceLen, err := strconv.Atoi(string(parts[0]))
	if err != nil {
		return domain.Frame{}, fmt.Errorf("parse nonce len: %w", err)
	}

	cipherLen, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return domain.Frame{}, fmt.Errorf("parse cipher len: %w", err)
	}

	padLen, err := strconv.Atoi(string(parts[2]))
	if err != nil {
		return domain.Frame{}, fmt.Errorf("parse padding len: %w", err)
	}

	payload := parts[3]
	if len(payload) != nonceLen+cipherLen {
		return domain.Frame{}, fmt.Errorf("payload length mismatch")
	}

	frame := domain.Frame{}
	frame.Nonce = byteutil.Clone(payload[:nonceLen])
	frame.Ciphertext = byteutil.Clone(payload[nonceLen : nonceLen+cipherLen])
	frame.Padding = byteutil.Clone(payload[nonceLen+cipherLen:])

	return frame, nil
}
