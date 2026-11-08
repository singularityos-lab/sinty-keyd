package tpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

type Fake struct {
	mu       sync.Mutex
	Name     string
	counters map[uint32]uint64
	next     uint32
	Failures int
}

func NewFake(name string) *Fake {
	return &Fake{Name: name, counters: map[uint32]uint64{}, next: 0x01810000}
}

func (f *Fake) Fingerprint() (string, error) {
	sum := sha256.Sum256([]byte("ek:" + f.Name))
	return hex.EncodeToString(sum[:]), nil
}

func (f *Fake) mask(pin string) []byte {
	sum := sha256.Sum256([]byte(f.Name + "\x00" + pin))
	return sum[:]
}

func (f *Fake) Seal(key []byte, pin string) ([]byte, []byte, error) {
	m := f.mask(pin)
	priv := make([]byte, len(key))
	for i := range key {
		priv[i] = key[i] ^ m[i%len(m)]
	}
	check := sha256.Sum256(append([]byte(f.Name), key...))
	return check[:], priv, nil
}

func (f *Fake) Unseal(pin string, pub, priv []byte) ([]byte, error) {
	m := f.mask(pin)
	key := make([]byte, len(priv))
	for i := range priv {
		key[i] = priv[i] ^ m[i%len(m)]
	}
	check := sha256.Sum256(append([]byte(f.Name), key...))
	if !bytes.Equal(check[:], pub) {
		f.mu.Lock()
		f.Failures++
		f.mu.Unlock()
		return nil, ErrWrongPIN
	}
	return key, nil
}

func (f *Fake) NewCounter() (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	f.counters[f.next] = 0
	return f.next, nil
}

func (f *Fake) Counter(index uint32) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.counters[index]
	if !ok {
		return 0, errors.New("no such counter")
	}
	return v, nil
}

func (f *Fake) Bump(index uint32) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.counters[index]; !ok {
		return 0, errors.New("no such counter")
	}
	f.counters[index]++
	return f.counters[index], nil
}
