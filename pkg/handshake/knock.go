package handshake

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/purpleproto/core/internal/byteutil"
	"github.com/purpleproto/core/pkg/config"
	"github.com/purpleproto/core/pkg/domain"
)

type Result struct {
	Mode     domain.Mode
	Response []byte
}

type Service struct {
	cfg config.Config
}

func NewService(cfg config.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &Service{cfg: cfg}, nil
}

func (s *Service) ComputeHeader(ts time.Time) []byte {
	mac := hmac.New(sha256.New, []byte(s.cfg.MasterPassword))

	var raw [8]byte
	binary.BigEndian.AppendUint64(raw[:], uint64(ts.Unix()))

	mac.Write(raw[:])
	sum := mac.Sum(nil)

	return sum[:s.cfg.HeaderSize]
}

func (s *Service) Inspect(attempt domain.HandshakeAttempt) Result {
	if s.matches(attempt.Header, attempt.ObservedAt) {
		return Result{Mode: domain.ModeTunnel}
	}

	return Result{Mode: domain.ModeFallback, Response: byteutil.Clone(s.cfg.HTTPFallback)}
}

func (s *Service) matches(observed []byte, now time.Time) bool {
	for _, candidate := range s.candidateTime(now) {
		expected := s.ComputeHeader(candidate)

		if byteutil.ConstantTimePrefix(observed, expected) {
			return true
		}
	}
	return false
}

func (s *Service) candidateTime(now time.Time) []time.Time {
	start := now.Add(-s.cfg.Window.Past).Unix()
	end := now.Add(s.cfg.Window.Future).Unix()
	out := make([]time.Time, 0, end-start+1)

	for ts := start; ts <= end; ts++ {
		out = append(out, time.Unix(ts, 0).UTC())
	}
	return out
}
