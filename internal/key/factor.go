package key

import (
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/singularityos-lab/sinty-keyd/internal/fido2"
	"github.com/singularityos-lab/sinty-keyd/internal/keyfile"
	"github.com/singularityos-lab/sinty-keyd/internal/seal"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

const (
	RelyingParty = "sinty-key"
	MaxFactors   = 8
	MaxNameLen   = 64
)

var (
	ErrFactorRequired = errors.New("this Key needs one of its security keys")
	ErrUnknownFactor  = errors.New("this security key is not registered with the Key")
	ErrFactorExists   = errors.New("this security key is already registered with the Key")
	ErrTooManyFactors = errors.New("this Key already has the most security keys it can hold")
	ErrNoFactor       = errors.New("no such security key on this Key")
)

type SecondFactor interface {
	Secret(rpID string, ids [][]byte, salt []byte) ([]byte, []byte, error)
}

type Registrar interface {
	SecondFactor
	Register(rpID, pin string, exclude [][]byte) ([]byte, error)
}

func mask(data, factor []byte) []byte {
	out := append([]byte(nil), data...)
	if factor == nil {
		return out
	}
	pad := make([]byte, len(data))
	io.ReadFull(hkdf.New(sha256.New, factor, nil, []byte("sinty-key factor tpm v1")), pad)
	for i := range out {
		out[i] ^= pad[i]
	}
	seal.Wipe(pad)
	return out
}

func (k *Key) touch() ([]byte, error) {
	h := k.Header
	if !h.Strong() {
		return nil, nil
	}
	if k.Second == nil {
		return nil, ErrFactorRequired
	}
	ids := make([][]byte, len(h.Factors))
	for i := range h.Factors {
		ids[i] = h.Factors[i].ID
	}
	id, out, err := k.Second.Secret(RelyingParty, ids, h.FactorSalt)
	if errors.Is(err, fido2.ErrNoCredential) {
		return nil, ErrUnknownFactor
	}
	if err != nil {
		return nil, err
	}
	defer seal.Wipe(out)
	f := h.Factor(id)
	if f == nil {
		return nil, ErrUnknownFactor
	}
	factor, err := seal.Unwrap(f.Wrapped, out)
	if err != nil {
		return nil, ErrUnknownFactor
	}
	return factor, nil
}

func (k *Key) factorOf(master []byte) ([]byte, error) {
	if !k.Header.Strong() {
		return nil, nil
	}
	return seal.Unwrap(k.Header.FactorKey, master)
}

func (k *Key) unlockGuest(pin string) ([]byte, error) {
	factor, err := k.touch()
	if err != nil {
		return nil, err
	}
	defer seal.Wipe(factor)
	return k.guest(pin, factor)
}

func (k *Key) dropOtherSlots(t tpm.TPM) {
	here := ""
	if t != nil {
		here, _ = t.Fingerprint()
	}
	for i := range k.Header.Slots {
		if k.Header.Slots[i].PC != here {
			k.Header.Slots[i].Public = nil
			k.Header.Slots[i].Private = nil
		}
	}
}

func (k *Key) AddFactor(t tpm.TPM, pin string, reg Registrar, name, devicePIN string) ([]byte, error) {
	if len(name) == 0 || len(name) > MaxNameLen {
		return nil, errors.New("a security key needs a short name")
	}
	if len(k.Header.Factors) >= MaxFactors {
		return nil, ErrTooManyFactors
	}
	master, err := k.unlockGuest(pin)
	if err != nil {
		return nil, err
	}
	defer seal.Wipe(master)
	h := k.Header
	strong := h.Strong()
	var factor []byte
	if strong {
		if factor, err = k.factorOf(master); err != nil {
			return nil, err
		}
	} else if factor, err = seal.Random(seal.KeySize); err != nil {
		return nil, err
	}
	defer seal.Wipe(factor)
	salt := h.FactorSalt
	if !strong {
		if salt, err = seal.Random(32); err != nil {
			return nil, err
		}
	}
	known := make([][]byte, len(h.Factors))
	for i := range h.Factors {
		known[i] = h.Factors[i].ID
	}
	id, err := reg.Register(RelyingParty, devicePIN, known)
	if errors.Is(err, fido2.ErrExcluded) {
		return nil, ErrFactorExists
	}
	if err != nil {
		return nil, err
	}
	if h.Factor(id) != nil {
		return nil, ErrFactorExists
	}
	_, out, err := reg.Secret(RelyingParty, [][]byte{id}, salt)
	if err != nil {
		return nil, err
	}
	wrapped, err := seal.Wrap(factor, out)
	seal.Wipe(out)
	if err != nil {
		return nil, err
	}
	entry := keyfile.Factor{ID: id, Name: name, Wrapped: wrapped, Added: k.Now().UTC().Truncate(time.Second)}
	if strong {
		h.Factors = append(h.Factors, entry)
		return id, k.save(master)
	}
	fk, err := seal.Wrap(factor, master)
	if err != nil {
		return nil, err
	}
	h.Factors = []keyfile.Factor{entry}
	h.FactorSalt, h.FactorKey, h.Format = salt, fk, keyfile.Format
	k.dropOtherSlots(t)
	return id, k.setPIN(t, master, pin)
}

func (k *Key) RemoveFactor(t tpm.TPM, pin string, id []byte) error {
	master, err := k.unlockGuest(pin)
	if err != nil {
		return err
	}
	defer seal.Wipe(master)
	return k.removeFactor(t, master, pin, id)
}

func (k *Key) removeFactor(t tpm.TPM, master []byte, pin string, id []byte) error {
	h := k.Header
	at := -1
	for i := range h.Factors {
		if string(h.Factors[i].ID) == string(id) {
			at = i
		}
	}
	if at < 0 {
		return ErrNoFactor
	}
	h.Factors = append(h.Factors[:at], h.Factors[at+1:]...)
	if h.Strong() {
		return k.save(master)
	}
	h.Factors, h.FactorSalt, h.FactorKey, h.Format = nil, nil, nil, keyfile.FormatBase
	k.dropOtherSlots(t)
	return k.setPIN(t, master, pin)
}

func (k *Key) RecoverWithoutFactors(t tpm.TPM, code, pin string) error {
	if len(pin) < MinPIN {
		return ErrShortPIN
	}
	master, err := k.recoveryMaster(code)
	if err != nil {
		return err
	}
	defer seal.Wipe(master)
	if !k.Header.Strong() {
		return k.setPIN(t, master, pin)
	}
	h := k.Header
	h.Factors, h.FactorSalt, h.FactorKey, h.Format = nil, nil, nil, keyfile.FormatBase
	k.dropOtherSlots(t)
	return k.setPIN(t, master, pin)
}
