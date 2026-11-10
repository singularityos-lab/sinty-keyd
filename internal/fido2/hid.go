package fido2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Transport interface {
	CBOR(req []byte) ([]byte, error)
	Close() error
}

const (
	report       = 64
	hidInit      = 0x86
	hidCBOR      = 0x90
	hidCancel    = 0x91
	hidKeepalive = 0xbb
	hidError     = 0xbf
	broadcast    = 0xffffffff
)

var ErrTimeout = errors.New("the security key did not answer")

type HID struct {
	f       *os.File
	cid     uint32
	Timeout time.Duration
}

func Devices(sysfs string) []string {
	var out []string
	matches, _ := filepath.Glob(filepath.Join(sysfs, "class/hidraw/hidraw*/device/report_descriptor"))
	for _, m := range matches {
		desc, err := os.ReadFile(m)
		if err != nil || !bytes.Contains(desc, []byte{0x06, 0xd0, 0xf1}) {
			continue
		}
		name := filepath.Base(filepath.Dir(filepath.Dir(m)))
		if strings.HasPrefix(name, "hidraw") {
			out = append(out, "/dev/"+name)
		}
	}
	return out
}

func OpenHID(path string) (*HID, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return newHID(f)
}

func newHID(f *os.File) (*HID, error) {
	h := &HID{f: f, cid: broadcast, Timeout: 30 * time.Second}
	nonce := make([]byte, 8)
	rand.Read(nonce)
	if err := h.send(hidInit, nonce); err != nil {
		f.Close()
		return nil, err
	}
	for {
		cmd, data, err := h.recv(2 * time.Second)
		if err != nil {
			f.Close()
			return nil, err
		}
		if cmd == hidInit && len(data) >= 17 && bytes.Equal(data[:8], nonce) {
			h.cid = binary.BigEndian.Uint32(data[8:12])
			return h, nil
		}
	}
}

func (h *HID) Close() error { return h.f.Close() }

func (h *HID) send(cmd byte, data []byte) error {
	if len(data) > 7609 {
		return errors.New("fido2: message too long")
	}
	pkt := make([]byte, report+1)
	binary.BigEndian.PutUint32(pkt[1:5], h.cid)
	pkt[5] = cmd
	binary.BigEndian.PutUint16(pkt[6:8], uint16(len(data)))
	n := copy(pkt[8:], data)
	if _, err := h.f.Write(pkt); err != nil {
		return err
	}
	for seq := byte(0); n < len(data); seq++ {
		pkt = make([]byte, report+1)
		binary.BigEndian.PutUint32(pkt[1:5], h.cid)
		pkt[5] = seq
		n += copy(pkt[6:], data[n:])
		if _, err := h.f.Write(pkt); err != nil {
			return err
		}
	}
	return nil
}

func (h *HID) read(wait time.Duration) ([]byte, error) {
	h.f.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, report)
	for {
		n, err := h.f.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, ErrTimeout
		}
		if err != nil {
			return nil, err
		}
		if n >= 7 && binary.BigEndian.Uint32(buf[:4]) == h.cid {
			return buf[:n], nil
		}
	}
}

func (h *HID) recv(wait time.Duration) (byte, []byte, error) {
	first, err := h.read(wait)
	if err != nil {
		return 0, nil, err
	}
	cmd := first[4]
	if cmd&0x80 == 0 {
		return 0, nil, errors.New("fido2: continuation packet out of order")
	}
	size := int(binary.BigEndian.Uint16(first[5:7]))
	data := append([]byte(nil), first[7:min(len(first), 7+size)]...)
	for seq := byte(0); len(data) < size; seq++ {
		pkt, err := h.read(wait)
		if err != nil {
			return 0, nil, err
		}
		if pkt[4] != seq {
			return 0, nil, errors.New("fido2: packet sequence broken")
		}
		data = append(data, pkt[5:min(len(pkt), 5+size-len(data))]...)
	}
	return cmd, data, nil
}

func (h *HID) CBOR(req []byte) ([]byte, error) {
	if err := h.send(hidCBOR, req); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(h.Timeout)
	for time.Now().Before(deadline) {
		cmd, data, err := h.recv(time.Until(deadline))
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				h.send(hidCancel, nil)
			}
			return nil, err
		}
		switch cmd {
		case hidKeepalive:
			continue
		case hidError:
			if len(data) > 0 {
				return nil, fmt.Errorf("fido2: transport error 0x%02x", data[0])
			}
			return nil, errors.New("fido2: transport error")
		case hidCBOR:
			return data, nil
		}
	}
	h.send(hidCancel, nil)
	return nil, ErrTimeout
}
