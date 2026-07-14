package bip32secp256k1

import (
	"crypto/sha256"
	"crypto/subtle"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Indexes = func() [256]int16 {
	var indexes [256]int16
	for i := range indexes {
		indexes[i] = -1
	}
	for i := range base58Alphabet {
		indexes[base58Alphabet[i]] = int16(i)
	}
	return indexes
}()

func encodeBase58Check(payload []byte) (string, error) {
	if len(payload) != SerializedKeySize {
		return "", ErrInvalidEncoding
	}
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	full := make([]byte, 0, SerializedKeySize+ChecksumSize)
	full = append(full, payload...)
	full = append(full, second[:ChecksumSize]...)
	encoded := base58Encode(full)
	clear(full)
	if len(encoded) != EncodedKeySize {
		return "", ErrInvalidEncoding
	}
	return encoded, nil
}

func decodeBase58Check(encoded string) ([]byte, error) {
	if len(encoded) != EncodedKeySize {
		return nil, ErrInvalidEncoding
	}
	full, ok := base58Decode(encoded)
	if !ok || len(full) != SerializedKeySize+ChecksumSize {
		return nil, ErrInvalidEncoding
	}
	if base58Encode(full) != encoded {
		clear(full)
		return nil, ErrInvalidEncoding
	}
	payload := full[:SerializedKeySize]
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	if subtle.ConstantTimeCompare(full[SerializedKeySize:], second[:ChecksumSize]) != 1 {
		clear(full)
		return nil, ErrInvalidChecksum
	}
	out := make([]byte, SerializedKeySize)
	copy(out, payload)
	clear(full)
	return out, nil
}

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	size := (len(input)-zeros)*138/100 + 1
	digits := make([]byte, size)
	length := 0
	for _, b := range input[zeros:] {
		carry := int(b)
		used := 0
		for j := len(digits) - 1; (carry != 0 || used < length) && j >= 0; j-- {
			carry += 256 * int(digits[j])
			digits[j] = byte(carry % 58)
			carry /= 58
			used++
		}
		length = used
	}

	start := len(digits) - length
	out := make([]byte, zeros+length)
	for i := range zeros {
		out[i] = base58Alphabet[0]
	}
	for i, digit := range digits[start:] {
		out[zeros+i] = base58Alphabet[digit]
	}
	clear(digits)
	return string(out)
}

func base58Decode(input string) ([]byte, bool) {
	if input == "" {
		return nil, true
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == base58Alphabet[0] {
		zeros++
	}

	size := (len(input)-zeros)*733/1000 + 1
	decoded := make([]byte, size)
	length := 0
	for i := zeros; i < len(input); i++ {
		value := base58Indexes[input[i]]
		if value < 0 {
			clear(decoded)
			return nil, false
		}
		carry := int(value)
		used := 0
		for j := len(decoded) - 1; (carry != 0 || used < length) && j >= 0; j-- {
			carry += 58 * int(decoded[j])
			decoded[j] = byte(carry)
			carry >>= 8
			used++
		}
		if carry != 0 {
			clear(decoded)
			return nil, false
		}
		length = used
	}

	start := len(decoded) - length
	out := make([]byte, zeros+length)
	copy(out[zeros:], decoded[start:])
	clear(decoded)
	return out, true
}
