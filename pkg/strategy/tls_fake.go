package strategy

import (
	"encoding/binary"
	"fmt"

	"github.com/purpleproto/core/internal/byteutil"
	"github.com/purpleproto/core/pkg/domain"
)

const (
	tlsRecordTypeApplicationData = 0x17
	tlsVersion12Major            = 0x03
	tlsVersion12Minor            = 0x03
)

type TLSFake struct{}

func (t TLSFake) Name() domain.StrategyName { return domain.StrategyTLSFake }

func (t TLSFake) Wrap(frame domain.Frame) (domain.Frame, error) {
	body := serializeFrameBody(frame)
	if len(body) > 0xFFFF {
		return domain.Frame{}, fmt.Errorf("frame too large for tls fake record")
	}

	out := make([]byte, 5+len(body))

	out[0] = tlsRecordTypeApplicationData
	out[1] = tlsVersion12Major
	out[2] = tlsVersion12Minor

	binary.BigEndian.PutUint16(out[3:5], uint16(len(body)))
	copy(out[5:], body)
	frame.Ciphertext = out

	return frame, nil
}

func UnwrapTLSFakeFrame(record []byte) (domain.Frame, error) {
	if len(record) < 5 {
		return domain.Frame{}, fmt.Errorf("record too short")
	}

	if record[0] != tlsRecordTypeApplicationData ||
		record[1] != tlsVersion12Major ||
		record[2] != tlsVersion12Minor {
		return domain.Frame{}, fmt.Errorf("unexpected tls fake record header")
	}

	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen != len(record)-5 {
		return domain.Frame{}, fmt.Errorf("record size mismatch")
	}

	frame, err := deserializeFrameBody(record[5:])
	if err != nil {
		return domain.Frame{}, err
	}

	frame.Ciphertext = byteutil.Clone(frame.Ciphertext)
	return frame, nil
}
