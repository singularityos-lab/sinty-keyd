package keyfile

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	Format = 1
	Dir    = ".sinty-key"
	Name   = "key.json"
)

var (
	ErrNoKey    = errors.New("not a Sinty Key")
	ErrTampered = errors.New("key header does not match its key")
)

type Slot struct {
	PC         string    `json:"pc"`
	Name       string    `json:"name"`
	Public     []byte    `json:"public"`
	Private    []byte    `json:"private"`
	Counter    uint32    `json:"counter"`
	Generation uint64    `json:"generation"`
	PINEpoch   uint64    `json:"pin_epoch"`
	Firmware   string    `json:"firmware,omitempty"`
	LastUsed   time.Time `json:"last_used"`
}

type Header struct {
	Format   int       `json:"format"`
	ID       string    `json:"id"`
	Level    string    `json:"level"`
	Owner    string    `json:"owner,omitempty"`
	Created  time.Time `json:"created"`
	Secret   []byte    `json:"secret"`
	Guest    []byte    `json:"guest"`
	Recovery []byte    `json:"recovery"`
	PINEpoch uint64    `json:"pin_epoch"`
	Slots    []Slot    `json:"slots"`
	MAC      []byte    `json:"mac,omitempty"`
}

func Path(root string) string {
	return filepath.Join(root, Dir, Name)
}

func Read(root string) (*Header, error) {
	data, err := os.ReadFile(Path(root))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	var h Header
	if err := json.Unmarshal(data, &h); err != nil || h.Format == 0 {
		return nil, ErrNoKey
	}
	if h.Format > Format {
		return nil, errors.New("key was made by a newer system")
	}
	return &h, nil
}

func macKey(master []byte) []byte {
	k := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, master, nil, []byte("sinty-key header v1")), k)
	return k
}

func (h *Header) digest(master []byte) ([]byte, error) {
	c := *h
	c.MAC = nil
	body, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, macKey(master))
	m.Write(body)
	return m.Sum(nil), nil
}

func (h *Header) Sign(master []byte) error {
	d, err := h.digest(master)
	if err != nil {
		return err
	}
	h.MAC = d
	return nil
}

func (h *Header) Verify(master []byte) error {
	d, err := h.digest(master)
	if err != nil {
		return err
	}
	if !hmac.Equal(d, h.MAC) {
		return ErrTampered
	}
	return nil
}

func (h *Header) Slot(pc string) *Slot {
	for i := range h.Slots {
		if h.Slots[i].PC == pc {
			return &h.Slots[i]
		}
	}
	return nil
}

func (h *Header) Remove(pc string) bool {
	for i := range h.Slots {
		if h.Slots[i].PC == pc {
			h.Slots = append(h.Slots[:i], h.Slots[i+1:]...)
			return true
		}
	}
	return false
}

func Write(root string, h *Header) error {
	dir := filepath.Join(root, Dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".key-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), Path(root)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
