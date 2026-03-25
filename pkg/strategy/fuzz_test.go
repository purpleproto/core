package strategy

import "testing"

func FuzzDeserializeHTTPPostFrame(f *testing.F) {
	seed := []byte("POST /api/v1/get HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nabcde")
	f.Add(seed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		DesearializeHTTPPostFrame(raw)
	})
}

func FuzzUnwrapTLSFakeFrame(f *testing.F) {
	f.Add([]byte{0x17, 0x03, 0x03, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, raw []byte) {
		UnwrapTLSFakeFrame(raw)
	})
}
