package byteutil

import "crypto/subtle"

func Clone(src []byte) []byte {
	if src == nil {
		return nil
	}

	out := make([]byte, len(src))
	copy(out, src)

	return out
}

func ConstantTimePrefix(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}

	return subtle.ConstantTimeCompare(left, right) == 1
}
