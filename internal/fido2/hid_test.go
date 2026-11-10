package fido2

import (
	"bytes"
	"encoding/binary"
	"os"
	"syscall"
	"testing"
)

type device struct {
	f    *os.File
	soft *Soft
	cid  uint32
}

func (d *device) write(cid uint32, cmd byte, data []byte) {
	pkt := make([]byte, report)
	binary.BigEndian.PutUint32(pkt[:4], cid)
	pkt[4] = cmd
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(data)))
	n := copy(pkt[7:], data)
	d.f.Write(pkt)
	for seq := byte(0); n < len(data); seq++ {
		pkt = make([]byte, report)
		binary.BigEndian.PutUint32(pkt[:4], cid)
		pkt[4] = seq
		n += copy(pkt[5:], data[n:])
		d.f.Write(pkt)
	}
}

func (d *device) serve(t *testing.T) {
	buf := make([]byte, report+1)
	var msg []byte
	var want int
	var cmd byte
	for {
		n, err := d.f.Read(buf)
		if err != nil {
			return
		}
		if n != report+1 || buf[0] != 0 {
			t.Errorf("report of %d bytes with id %d", n, buf[0])
			return
		}
		pkt := buf[1:]
		cid := binary.BigEndian.Uint32(pkt[:4])
		if pkt[4]&0x80 != 0 {
			cmd = pkt[4]
			want = int(binary.BigEndian.Uint16(pkt[5:7]))
			msg = append([]byte(nil), pkt[7:7+min(want, report-7)]...)
		} else {
			msg = append(msg, pkt[5:5+min(want-len(msg), report-5)]...)
		}
		if len(msg) < want {
			continue
		}
		switch cmd {
		case hidInit:
			out := append(append([]byte(nil), msg[:8]...), 0, 0, 0, 0, 2, 1, 0, 0, 4)
			binary.BigEndian.PutUint32(out[8:12], d.cid)
			d.write(cid, hidInit, out)
		case hidCBOR:
			if cid != d.cid {
				d.write(cid, hidError, []byte{0x0b})
				continue
			}
			d.write(cid, hidKeepalive, []byte{2})
			res, _ := d.soft.CBOR(msg)
			d.write(cid, hidCBOR, res)
		}
	}
}

func TestOverHID(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skip(err)
	}
	host, dev := os.NewFile(uintptr(fds[0]), "host"), os.NewFile(uintptr(fds[1]), "device")
	defer dev.Close()
	d := &device{f: dev, soft: NewSoft(), cid: 0x1c2d3e4f}
	go d.serve(t)
	h, err := newHID(host)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.cid != d.cid {
		t.Fatalf("channel %x", h.cid)
	}
	c := &Client{T: h}
	id, err := c.Register("sinty-key", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{7}, 32)
	var ids [][]byte
	for i := 0; i < 40; i++ {
		ids = append(ids, bytes.Repeat([]byte{byte(i)}, 64))
	}
	ids = append(ids, id)
	got, out, err := c.Secret("sinty-key", ids, salt)
	if err != nil || !bytes.Equal(got, id) || len(out) != 32 {
		t.Fatalf("secret over HID: %v", err)
	}
	_, again, _ := c.Secret("sinty-key", [][]byte{id}, salt)
	if !bytes.Equal(out, again) {
		t.Fatal("the secret changed")
	}
}

func TestDevices(t *testing.T) {
	sys := t.TempDir()
	put := func(name string, desc []byte) {
		dir := sys + "/class/hidraw/" + name + "/device"
		os.MkdirAll(dir, 0o755)
		os.WriteFile(dir+"/report_descriptor", desc, 0o644)
	}
	put("hidraw0", []byte{0x05, 0x01, 0x09, 0x06})
	put("hidraw3", []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01})
	got := Devices(sys)
	if len(got) != 1 || got[0] != "/dev/hidraw3" {
		t.Fatalf("devices: %v", got)
	}
}
