package fido2

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

type Soft struct {
	mu       sync.Mutex
	PIN      string
	Deny     bool
	agree    *ecdh.PrivateKey
	token    []byte
	creds    map[string]softCred
	counter  uint32
	Requests int
}

type softCred struct {
	rp     [32]byte
	random []byte
	key    *ecdsa.PrivateKey
}

func NewSoft() *Soft {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	return &Soft{agree: k, creds: map[string]softCred{}, token: random(32)}
}

func (s *Soft) Close() error { return nil }

func status(code byte) []byte { return []byte{code} }

func ok(m Map) []byte {
	body, _ := Encode(m)
	return append([]byte{0}, body...)
}

func (s *Soft) CBOR(req []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests++
	if len(req) == 0 {
		return status(0x01), nil
	}
	var params map[any]any
	if len(req) > 1 {
		v, _, err := Decode(req[1:])
		if err != nil {
			return status(0x12), nil
		}
		var isMap bool
		if params, isMap = asMap(v); !isMap {
			return status(0x12), nil
		}
	}
	switch req[0] {
	case cmdGetInfo:
		opts := Map{{"rk", false}, {"up", true}, {"clientPin", s.PIN != ""}, {"pinUvAuthToken", true}}
		return ok(Map{
			{int64(1), []any{"FIDO_2_0", "FIDO_2_1"}},
			{int64(2), []any{"hmac-secret"}},
			{int64(3), make([]byte, 16)},
			{int64(4), opts},
			{int64(6), []any{int64(2), int64(1)}},
		}), nil
	case cmdClientPIN:
		return s.clientPIN(params), nil
	case cmdMakeCredential:
		return s.makeCredential(params), nil
	case cmdGetAssertion:
		return s.getAssertion(params), nil
	}
	return status(0x01), nil
}

func protocolOf(v any) Protocol {
	if n, _ := v.(int64); n == 2 {
		return ProtocolV2{}
	}
	return ProtocolV1{}
}

func (s *Soft) shared(p Protocol, peer any) ([]byte, bool) {
	pub, err := parseCoseKey(peer)
	if err != nil {
		return nil, false
	}
	z, err := s.agree.ECDH(pub)
	if err != nil {
		return nil, false
	}
	return p.KDF(z), true
}

func (s *Soft) clientPIN(m map[any]any) []byte {
	p := protocolOf(m[int64(1)])
	switch m[int64(2)] {
	case int64(pinGetKeyAgreement):
		return ok(Map{{int64(1), coseKey(s.agree.PublicKey())}})
	case int64(pinGetToken), int64(pinGetTokenPerm):
		if s.PIN == "" {
			return status(0x35)
		}
		shared, good := s.shared(p, m[int64(3)])
		if !good {
			return status(0x12)
		}
		enc, _ := bytesAt(m, int64(6))
		got, err := p.Decrypt(shared, enc)
		want := sha256.Sum256([]byte(s.PIN))
		if err != nil || !bytes.Equal(got, want[:16]) {
			return status(0x31)
		}
		s.token = random(32)
		tokEnc, _ := p.Encrypt(shared, s.token)
		return ok(Map{{int64(2), tokEnc}})
	}
	return status(0x02)
}

func (s *Soft) authData(rp [32]byte, flags byte, attested []byte, ext Map) []byte {
	s.counter++
	var buf bytes.Buffer
	buf.Write(rp[:])
	if attested != nil {
		flags |= 0x40
	}
	if ext != nil {
		flags |= 0x80
	}
	buf.WriteByte(flags | 0x01)
	binary.Write(&buf, binary.BigEndian, s.counter)
	buf.Write(attested)
	if ext != nil {
		e, _ := Encode(ext)
		buf.Write(e)
	}
	return buf.Bytes()
}

func (s *Soft) makeCredential(m map[any]any) []byte {
	cdh, _ := bytesAt(m, int64(1))
	rp, _ := asMap(m[int64(2)])
	rpID, _ := rp["id"].(string)
	if len(cdh) != 32 || rpID == "" {
		return status(0x14)
	}
	var flags byte
	if s.PIN != "" {
		auth, has := bytesAt(m, int64(8))
		if !has {
			return status(0x36)
		}
		if !hmac.Equal(auth, protocolOf(m[int64(9)]).Authenticate(s.token, cdh)) {
			return status(0x33)
		}
		flags |= 0x04
	}
	if list, isList := m[int64(5)].([]any); isList {
		for _, e := range list {
			d, _ := asMap(e)
			cid, _ := bytesAt(d, "id")
			if c, found := s.creds[string(cid)]; found && c.rp == sha256.Sum256([]byte(rpID)) {
				return status(0x19)
			}
		}
	}
	if s.Deny {
		return status(0x27)
	}
	ext, _ := asMap(m[int64(6)])
	wantSecret, _ := ext["hmac-secret"].(bool)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := random(48)
	s.creds[string(id)] = softCred{rp: sha256.Sum256([]byte(rpID)), random: random(32), key: key}
	var att bytes.Buffer
	att.Write(make([]byte, 16))
	binary.Write(&att, binary.BigEndian, uint16(len(id)))
	att.Write(id)
	pub, _ := Encode(Map{
		{int64(1), int64(2)}, {int64(3), int64(-7)}, {int64(-1), int64(1)},
		{int64(-2), key.X.FillBytes(make([]byte, 32))}, {int64(-3), key.Y.FillBytes(make([]byte, 32))},
	})
	att.Write(pub)
	var extOut Map
	if wantSecret {
		extOut = Map{{"hmac-secret", true}}
	}
	ad := s.authData(sha256.Sum256([]byte(rpID)), flags, att.Bytes(), extOut)
	return ok(Map{{int64(1), "none"}, {int64(2), ad}, {int64(3), Map{}}})
}

func (s *Soft) getAssertion(m map[any]any) []byte {
	rpID, _ := m[int64(1)].(string)
	cdh, _ := bytesAt(m, int64(2))
	rp := sha256.Sum256([]byte(rpID))
	var id []byte
	var cred softCred
	if list, isList := m[int64(3)].([]any); isList {
		for _, e := range list {
			d, _ := asMap(e)
			cid, _ := bytesAt(d, "id")
			if c, found := s.creds[string(cid)]; found && c.rp == rp {
				id, cred = cid, c
				break
			}
		}
	}
	if id == nil {
		return status(0x2e)
	}
	if s.Deny {
		return status(0x27)
	}
	var extOut Map
	if ext, has := asMap(m[int64(4)]); has {
		if hs, has := asMap(ext["hmac-secret"]); has {
			p := protocolOf(hs[int64(4)])
			shared, good := s.shared(p, hs[int64(1)])
			if !good {
				return status(0x12)
			}
			saltEnc, _ := bytesAt(hs, int64(2))
			saltAuth, _ := bytesAt(hs, int64(3))
			if !hmac.Equal(saltAuth, p.Authenticate(shared, saltEnc)) {
				return status(0x33)
			}
			salts, err := p.Decrypt(shared, saltEnc)
			if err != nil || (len(salts) != 32 && len(salts) != 64) {
				return status(0x12)
			}
			var out []byte
			for i := 0; i < len(salts); i += 32 {
				h := hmac.New(sha256.New, cred.random)
				h.Write(salts[i : i+32])
				out = h.Sum(out)
			}
			enc, _ := p.Encrypt(shared, out)
			extOut = Map{{"hmac-secret", enc}}
		}
	}
	ad := s.authData(rp, 0, nil, extOut)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), cdh...))
	sig, _ := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	return ok(Map{{int64(1), Map{{"id", id}, {"type", "public-key"}}}, {int64(2), ad}, {int64(3), sig}})
}
