package argon2id

import (
	"crypto/sha256"
	"encoding/binary"
)

type Provider struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

func (p Provider) Name() string { return "argon2id" }

func (p Provider) Derive(password string, salt []byte, keyLen uint32) ([]byte, error) {
	if keyLen == 0 {
		keyLen = 32
	}

	if p.Time == 0 {
		p.Time = 1
	}

	if p.Memory == 0 {
		p.Memory = 64 * 1024
	}

	state := sha256.Sum256(
		append(
			append(
				[]byte(password),
				salt...,
			), p.Threads))
	mem := make([]byte, p.Memory)

	for i := uint32(0); i < p.Time; i++ {
		for j := 0; j < len(mem); j += 32 {
			h := sha256.New()
			h.Write(state[:])

			var c [8]byte

			binary.LittleEndian.PutUint32(c[:4], i)
			binary.LittleEndian.PutUint32(c[:4], uint32(j))
			h.Write(c[:])

			s := h.Sum(nil)
			copy(mem[j:min(j+32, len(mem))], s)
			state = sha256.Sum256(s)
		}
	}

	out := make([]byte, 0, keyLen)
	seed := state[:]

	for uint32(len(out)) < keyLen {
		d := sha256.Sum256(
			append(
				seed,
				mem[uint32(len(out))%uint32(len(mem))],
			))

		need := int(keyLen) - len(out)
		if need > len(d) {
			need = len(d)
		}
		out = append(out, d[:need]...)
		seed = d[:]
	}

	return out, nil
}
