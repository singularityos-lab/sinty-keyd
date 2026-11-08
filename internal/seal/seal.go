package seal

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize  = 32
	saltSize = 16
	BlobSize = saltSize + chacha20poly1305.NonceSizeX + KeySize + chacha20poly1305.Overhead
)

var ErrWrongSecret = errors.New("wrong secret")

func derive(secret, salt []byte) []byte {
	return argon2.IDKey(secret, salt, 3, 64*1024, 1, KeySize)
}

func Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func Wrap(key, secret []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}
	head, err := Random(saltSize + chacha20poly1305.NonceSizeX)
	if err != nil {
		return nil, err
	}
	dk := derive(secret, head[:saltSize])
	defer Wipe(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	return aead.Seal(head, head[saltSize:], key, nil), nil
}

func Unwrap(blob, secret []byte) ([]byte, error) {
	if len(blob) != BlobSize {
		return nil, errors.New("malformed wrapped key")
	}
	dk := derive(secret, blob[:saltSize])
	defer Wipe(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	key, err := aead.Open(nil, blob[saltSize:saltSize+chacha20poly1305.NonceSizeX], blob[saltSize+chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return nil, ErrWrongSecret
	}
	return key, nil
}

func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func RecoveryCode() (string, error) {
	raw, err := Random(16)
	if err != nil {
		return "", err
	}
	defer Wipe(raw)
	var out []byte
	var acc uint32
	bits, emitted := 0, 0
	for _, b := range raw {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			if emitted != 0 && emitted%5 == 0 {
				out = append(out, '-')
			}
			out = append(out, crockford[(acc>>bits)&0x1f])
			emitted++
		}
	}
	return string(out), nil
}

func NormalizeCode(code string) string {
	var out []byte
	n := 0
	for _, r := range code {
		switch {
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		case r == ' ' || r == '-':
			continue
		}
		switch r {
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if n != 0 && n%5 == 0 {
			out = append(out, '-')
		}
		out = append(out, byte(r))
		n++
	}
	return string(out)
}
