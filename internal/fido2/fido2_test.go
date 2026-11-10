package fido2

import (
	"bytes"
	"errors"
	"testing"
)

func TestCBORRoundTrip(t *testing.T) {
	in := Map{{int64(3), "c"}, {int64(1), []byte{1, 2}}, {"up", true}, {int64(-2), []any{int64(-7), "x"}}, {int64(24), uint64(70000)}}
	enc, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	v, rest, err := Decode(enc)
	if err != nil || len(rest) != 0 {
		t.Fatal(err, rest)
	}
	m := v.(map[any]any)
	if m[int64(3)] != "c" || !bytes.Equal(m[int64(1)].([]byte), []byte{1, 2}) || m["up"] != true || m[int64(24)] != int64(70000) {
		t.Fatalf("%v", m)
	}
	if enc[1] != 0x01 {
		t.Fatalf("keys not canonical: % x", enc)
	}
	for _, bad := range [][]byte{{0x5f}, {0x42, 1}, {0xa1, 0x41, 0, 1}, {0x18}} {
		if _, _, err := Decode(bad); err == nil {
			t.Errorf("accepted % x", bad)
		}
	}
}

func TestRegisterAndSecret(t *testing.T) {
	for _, pin := range []string{"", "4321"} {
		soft := NewSoft()
		soft.PIN = pin
		c := &Client{T: soft}
		id, err := c.Register("sinty-key", pin, nil)
		if err != nil {
			t.Fatalf("pin %q: %v", pin, err)
		}
		salt := bytes.Repeat([]byte{7}, 32)
		used, a, err := c.Secret("sinty-key", [][]byte{[]byte("other"), id}, salt)
		if err != nil || !bytes.Equal(used, id) {
			t.Fatal(err)
		}
		_, b, err := (&Client{T: soft}).Secret("sinty-key", [][]byte{id}, salt)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("secret not stable: %v", err)
		}
		_, other, _ := c.Secret("sinty-key", [][]byte{id}, bytes.Repeat([]byte{8}, 32))
		if bytes.Equal(a, other) {
			t.Fatal("the salt did not change the secret")
		}
		if _, _, err := c.Secret("another-rp", [][]byte{id}, salt); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("other rp: %v", err)
		}
	}
}

func TestPINAndPresence(t *testing.T) {
	soft := NewSoft()
	soft.PIN = "4321"
	if _, err := (&Client{T: soft}).Register("sinty-key", "", nil); !errors.Is(err, ErrPINRequired) {
		t.Fatalf("no pin: %v", err)
	}
	if _, err := (&Client{T: soft}).Register("sinty-key", "0000", nil); !errors.Is(err, ErrPINInvalid) {
		t.Fatalf("wrong pin: %v", err)
	}
	soft.PIN = ""
	soft.Deny = true
	if _, err := (&Client{T: soft}).Register("sinty-key", "", nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("not touched: %v", err)
	}
}

func TestProtocolOne(t *testing.T) {
	soft := NewSoft()
	c := &Client{T: soft}
	c.info = &Info{Extensions: []string{"hmac-secret"}, Options: map[string]bool{}, Protocols: []int64{1}}
	id, err := c.Register("sinty-key", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, a, err := c.Secret("sinty-key", [][]byte{id}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := (&Client{T: soft}).Secret("sinty-key", [][]byte{id}, make([]byte, 32))
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("protocol 1 and 2 disagree on the secret")
	}
}
