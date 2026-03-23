package strategy

import "github.com/purpleproto/core/pkg/domain"

type Strategy interface {
	Name() domain.StrategyName
	Wrap(frame domain.Frame) (domain.Frame, error)
}

type Chain struct {
	strategies []Strategy
}

func NewChain(strategies ...Strategy) Chain {
	return Chain{strategies: strategies}
}

func (c Chain) Apply(frame domain.Frame) (domain.Frame, error) {
	var err error

	for _, strategy := range c.strategies {
		frame, err = strategy.Wrap(frame)
		if err != nil {
			return domain.Frame{}, err
		}
	}
	return frame, nil
}
