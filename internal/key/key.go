package key

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/singularityos-lab/sinty-keyd/internal/keyfile"
	"github.com/singularityos-lab/sinty-keyd/internal/seal"
	"github.com/singularityos-lab/sinty-keyd/internal/tpm"
)

const (
	LevelBase = "base"
	Trusted   = "trusted"
	Guest     = "guest"
	MinPIN    = 4
)

var (
	ErrExists        = errors.New("this drive is already a Sinty Key")
	ErrWrongPIN      = errors.New("wrong PIN")
	ErrWrongCode     = errors.New("wrong recovery code")
	ErrCopy          = errors.New("this Key is an older copy; unlock it with the recovery code")
	ErrShortPIN      = errors.New("the PIN is too short")
	ErrNotRemembered = errors.New("this computer is not remembered by the Key")
)

type Key struct {
	Root   string
	Header *keyfile.Header
	Now    func() time.Time
}

func guestSecret(pin string, secret []byte) []byte {
	return append(append([]byte(pin), 0), secret...)
}

func Create(root, pin string) (*Key, string, error) {
	if len(pin) < MinPIN {
		return nil, "", ErrShortPIN
	}
	if _, err := keyfile.Read(root); err == nil {
		return nil, "", ErrExists
	} else if !errors.Is(err, keyfile.ErrNoKey) {
		return nil, "", err
	}
	master, err := seal.Random(seal.KeySize)
	if err != nil {
		return nil, "", err
	}
	defer seal.Wipe(master)
	secret, err := seal.Random(32)
	if err != nil {
		return nil, "", err
	}
	id, err := seal.Random(8)
	if err != nil {
		return nil, "", err
	}
	code, err := seal.RecoveryCode()
	if err != nil {
		return nil, "", err
	}
	k := &Key{Root: root, Now: time.Now}
	h := &keyfile.Header{
		Format:   keyfile.Format,
		ID:       hex.EncodeToString(id),
		Level:    LevelBase,
		Created:  k.Now().UTC().Truncate(time.Second),
		Secret:   secret,
		PINEpoch: 1,
		Slots:    []keyfile.Slot{},
	}
	if h.Guest, err = seal.Wrap(master, guestSecret(pin, secret)); err != nil {
		return nil, "", err
	}
	if h.Recovery, err = seal.Wrap(master, []byte(code)); err != nil {
		return nil, "", err
	}
	k.Header = h
	if err := k.save(master); err != nil {
		return nil, "", err
	}
	return k, code, nil
}

func Open(root string) (*Key, error) {
	h, err := keyfile.Read(root)
	if err != nil {
		return nil, err
	}
	return &Key{Root: root, Header: h, Now: time.Now}, nil
}

func (k *Key) save(master []byte) error {
	if err := k.Header.Sign(master); err != nil {
		return err
	}
	return keyfile.Write(k.Root, k.Header)
}

func (k *Key) guest(pin string) ([]byte, error) {
	master, err := seal.Unwrap(k.Header.Guest, guestSecret(pin, k.Header.Secret))
	if errors.Is(err, seal.ErrWrongSecret) {
		return nil, ErrWrongPIN
	}
	if err != nil {
		return nil, err
	}
	if err := k.Header.Verify(master); err != nil {
		seal.Wipe(master)
		return nil, err
	}
	return master, nil
}

func (k *Key) slot(t tpm.TPM) (*keyfile.Slot, error) {
	if t == nil {
		return nil, nil
	}
	pc, err := t.Fingerprint()
	if err != nil {
		return nil, nil
	}
	s := k.Header.Slot(pc)
	if s == nil {
		return nil, nil
	}
	c, err := t.Counter(s.Counter)
	if err != nil {
		return nil, err
	}
	if s.Generation < c {
		return nil, ErrCopy
	}
	return s, nil
}

func (k *Key) advance(t tpm.TPM, s *keyfile.Slot, master []byte) error {
	c, err := t.Counter(s.Counter)
	if err != nil {
		return err
	}
	s.Generation = c + 1
	s.LastUsed = k.Now().UTC().Truncate(time.Second)
	if err := k.save(master); err != nil {
		return err
	}
	_, err = t.Bump(s.Counter)
	return err
}

func (k *Key) reseal(t tpm.TPM, s *keyfile.Slot, master []byte, pin string) error {
	pub, priv, err := t.Seal(master, pin)
	if err != nil {
		return err
	}
	s.Public, s.Private, s.PINEpoch = pub, priv, k.Header.PINEpoch
	return nil
}

func (k *Key) Unlock(t tpm.TPM, pin string) ([]byte, string, error) {
	s, err := k.slot(t)
	if err != nil {
		return nil, "", err
	}
	if s != nil && s.PINEpoch == k.Header.PINEpoch {
		master, err := t.Unseal(pin, s.Public, s.Private)
		if err == nil {
			if err := k.Header.Verify(master); err != nil {
				seal.Wipe(master)
				return nil, "", err
			}
			if err := k.advance(t, s, master); err != nil {
				seal.Wipe(master)
				return nil, "", err
			}
			return master, Trusted, nil
		}
	}
	master, err := k.guest(pin)
	if err != nil {
		return nil, "", err
	}
	if s != nil {
		if err := k.reseal(t, s, master, pin); err == nil && k.advance(t, s, master) == nil {
			return master, Trusted, nil
		}
	}
	return master, Guest, nil
}

func (k *Key) Remember(t tpm.TPM, pin, name, firmware string) error {
	pc, err := t.Fingerprint()
	if err != nil {
		return err
	}
	master, err := k.guest(pin)
	if err != nil {
		return err
	}
	defer seal.Wipe(master)
	if old := k.Header.Slot(pc); old != nil {
		old.Name = name
		if firmware != "" {
			old.Firmware = firmware
		}
		if err := k.reseal(t, old, master, pin); err != nil {
			return err
		}
		return k.advance(t, old, master)
	}
	counter, err := t.NewCounter()
	if err != nil {
		return err
	}
	s := keyfile.Slot{PC: pc, Name: name, Counter: counter, Firmware: firmware}
	if err := k.reseal(t, &s, master, pin); err != nil {
		return err
	}
	k.Header.Slots = append(k.Header.Slots, s)
	return k.advance(t, k.Header.Slot(pc), master)
}

func (k *Key) Forget(t tpm.TPM, pin, pc string) error {
	master, err := k.guest(pin)
	if err != nil {
		return err
	}
	defer seal.Wipe(master)
	s := k.Header.Slot(pc)
	if s == nil {
		return ErrNotRemembered
	}
	counter := s.Counter
	k.Header.Remove(pc)
	if err := k.save(master); err != nil {
		return err
	}
	if t != nil {
		if here, err := t.Fingerprint(); err == nil && here == pc {
			_, err = t.Bump(counter)
			return err
		}
	}
	return nil
}

func (k *Key) setPIN(t tpm.TPM, master []byte, pin string) error {
	if len(pin) < MinPIN {
		return ErrShortPIN
	}
	g, err := seal.Wrap(master, guestSecret(pin, k.Header.Secret))
	if err != nil {
		return err
	}
	k.Header.Guest = g
	k.Header.PINEpoch++
	if t != nil {
		if pc, err := t.Fingerprint(); err == nil {
			if s := k.Header.Slot(pc); s != nil {
				if err := k.reseal(t, s, master, pin); err != nil {
					return err
				}
				return k.advance(t, s, master)
			}
		}
	}
	return k.save(master)
}

func (k *Key) ChangePIN(t tpm.TPM, old, pin string) error {
	if len(pin) < MinPIN {
		return ErrShortPIN
	}
	master, err := k.guest(old)
	if err != nil {
		return err
	}
	defer seal.Wipe(master)
	return k.setPIN(t, master, pin)
}

func (k *Key) Recover(t tpm.TPM, code, pin string) error {
	if len(pin) < MinPIN {
		return ErrShortPIN
	}
	master, err := seal.Unwrap(k.Header.Recovery, []byte(seal.NormalizeCode(code)))
	if errors.Is(err, seal.ErrWrongSecret) {
		return ErrWrongCode
	}
	if err != nil {
		return err
	}
	defer seal.Wipe(master)
	if err := k.Header.Verify(master); err != nil {
		return err
	}
	return k.setPIN(t, master, pin)
}

func DataKey(master []byte) []byte {
	out := make([]byte, 64)
	io.ReadFull(hkdf.New(sha256.New, master, nil, []byte("sinty-key data v1")), out)
	return out
}
