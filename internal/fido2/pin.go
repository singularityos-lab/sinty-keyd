package fido2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Protocol interface {
	Version() int64
	KDF(z []byte) []byte
	Encrypt(key, plain []byte) ([]byte, error)
	Decrypt(key, data []byte) ([]byte, error)
	Authenticate(key, msg []byte) []byte
}

type ProtocolV1 struct{}

func (ProtocolV1) Version() int64 { return 1 }

func (ProtocolV1) KDF(z []byte) []byte {
	s := sha256.Sum256(z)
	return s[:]
}

func cbc(key, iv, data []byte, enc bool) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, errors.New("fido2: data is not a whole number of blocks")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	if enc {
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	} else {
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	}
	return out, nil
}

func (ProtocolV1) Encrypt(key, plain []byte) ([]byte, error) {
	return cbc(key, make([]byte, aes.BlockSize), plain, true)
}

func (ProtocolV1) Decrypt(key, data []byte) ([]byte, error) {
	return cbc(key, make([]byte, aes.BlockSize), data, false)
}

func (ProtocolV1) Authenticate(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:16]
}

type ProtocolV2 struct{}

func (ProtocolV2) Version() int64 { return 2 }

func (ProtocolV2) KDF(z []byte) []byte {
	salt := make([]byte, 32)
	out := make([]byte, 64)
	io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 HMAC key")), out[:32])
	io.ReadFull(hkdf.New(sha256.New, z, salt, []byte("CTAP2 AES key")), out[32:])
	return out
}

func (ProtocolV2) Encrypt(key, plain []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := cbc(key[32:], iv, plain, true)
	if err != nil {
		return nil, err
	}
	return append(iv, ct...), nil
}

func (ProtocolV2) Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("fido2: ciphertext too short")
	}
	return cbc(key[32:], data[:aes.BlockSize], data[aes.BlockSize:], false)
}

func (ProtocolV2) Authenticate(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key[:32])
	m.Write(msg)
	return m.Sum(nil)
}

func coseKey(pub *ecdh.PublicKey) Map {
	raw := pub.Bytes()
	return Map{
		{int64(1), int64(2)},
		{int64(3), int64(-25)},
		{int64(-1), int64(1)},
		{int64(-2), raw[1:33]},
		{int64(-3), raw[33:65]},
	}
}

func parseCoseKey(v any) (*ecdh.PublicKey, error) {
	m, ok := asMap(v)
	if !ok {
		return nil, errors.New("fido2: key agreement is not a map")
	}
	x, ok1 := bytesAt(m, int64(-2))
	y, ok2 := bytesAt(m, int64(-3))
	if !ok1 || !ok2 || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("fido2: bad key agreement")
	}
	return ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
}

func agree(p Protocol, peer *ecdh.PublicKey) (Map, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	z, err := priv.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	return coseKey(priv.PublicKey()), p.KDF(z), nil
}
