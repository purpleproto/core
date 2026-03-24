package strategy

import (
	"crypto/rand"
	"fmt"

	"github.com/purpleproto/core/internal/byteutil"
	"github.com/purpleproto/core/pkg/domain"
)

type Noise struct {
	Padding int
}

func (n Noise) Name() domain.StrategyName {
	return domain.StrategyNoise
}

func (n Noise) Wrap(frame domain.Frame) (domain.Frame, error) {
	if n.Padding <= 0 {
		return frame, nil
	}

	padding := make([]byte, n.Padding)
	if _, err := rand.Read(padding); err != nil {
		return domain.Frame{}, fmt.Errorf("generate noise padding: %w", err)
	}

	frame.Padding = byteutil.Clone(padding)
	return frame, nil
}
