package fido2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	cmdMakeCredential = 0x01
	cmdGetAssertion   = 0x02
	cmdGetInfo        = 0x04
	cmdClientPIN      = 0x06

	pinGetKeyAgreement = 0x02
	pinGetToken        = 0x05
	pinGetTokenPerm    = 0x09

	permMakeCredential = 0x01
	permGetAssertion   = 0x02
)

var (
	ErrNoCredential = errors.New("this security key is not registered with the Key")
	ErrDenied       = errors.New("the security key was not touched")
	ErrPINRequired  = errors.New("the security key needs its PIN")
	ErrPINInvalid   = errors.New("wrong security key PIN")
	ErrPINBlocked   = errors.New("the security key PIN is blocked")
	ErrNoHmacSecret = errors.New("this security key cannot keep a secret for the Key")
	ErrExcluded     = errors.New("this security key is already registered with the Key")
)

type StatusError byte

func (e StatusError) Error() string { return fmt.Sprintf("security key error 0x%02x", byte(e)) }

func statusErr(s byte) error {
	switch s {
	case 0x2e:
		return ErrNoCredential
	case 0x27, 0x2f:
		return ErrDenied
	case 0x19:
		return ErrExcluded
	case 0x36:
		return ErrPINRequired
	case 0x31:
		return ErrPINInvalid
	case 0x32, 0x34:
		return ErrPINBlocked
	}
	return StatusError(s)
}

type Info struct {
	Versions   []string
	Extensions []string
	Options    map[string]bool
	Protocols  []int64
	AAGUID     []byte
}

func (i Info) HasExtension(name string) bool {
	for _, e := range i.Extensions {
		if e == name {
			return true
		}
	}
	return false
}

type Client struct {
	T    Transport
	info *Info
}

func (c *Client) call(cmd byte, params Map) (map[any]any, error) {
	req := []byte{cmd}
	if params != nil {
		body, err := Encode(params)
		if err != nil {
			return nil, err
		}
		req = append(req, body...)
	}
	resp, err := c.T.CBOR(req)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, errors.New("fido2: empty answer")
	}
	if resp[0] != 0 {
		return nil, statusErr(resp[0])
	}
	if len(resp) == 1 {
		return map[any]any{}, nil
	}
	v, _, err := Decode(resp[1:])
	if err != nil {
		return nil, err
	}
	m, ok := asMap(v)
	if !ok {
		return nil, ErrCBOR
	}
	return m, nil
}

func textList(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func (c *Client) Info() (Info, error) {
	if c.info != nil {
		return *c.info, nil
	}
	m, err := c.call(cmdGetInfo, nil)
	if err != nil {
		return Info{}, err
	}
	info := Info{Versions: textList(m[int64(1)]), Extensions: textList(m[int64(2)]), Options: map[string]bool{}}
	info.AAGUID, _ = bytesAt(m, int64(3))
	if opts, ok := asMap(m[int64(4)]); ok {
		for k, v := range opts {
			if ks, ok := k.(string); ok {
				if b, ok := v.(bool); ok {
					info.Options[ks] = b
				}
			}
		}
	}
	if list, ok := m[int64(6)].([]any); ok {
		for _, e := range list {
			if n, ok := e.(int64); ok {
				info.Protocols = append(info.Protocols, n)
			}
		}
	}
	c.info = &info
	return info, nil
}

func (c *Client) protocol() (Protocol, error) {
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	for _, p := range info.Protocols {
		if p == 2 {
			return ProtocolV2{}, nil
		}
	}
	return ProtocolV1{}, nil
}

func (c *Client) keyAgreement(p Protocol) (Map, []byte, error) {
	m, err := c.call(cmdClientPIN, Map{{int64(1), p.Version()}, {int64(2), int64(pinGetKeyAgreement)}})
	if err != nil {
		return nil, nil, err
	}
	peer, err := parseCoseKey(m[int64(1)])
	if err != nil {
		return nil, nil, err
	}
	return agree(p, peer)
}

func (c *Client) token(p Protocol, pin, rpID string, perms int64) ([]byte, error) {
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	ka, shared, err := c.keyAgreement(p)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(pin))
	enc, err := p.Encrypt(shared, h[:16])
	if err != nil {
		return nil, err
	}
	params := Map{{int64(1), p.Version()}, {int64(3), ka}, {int64(6), enc}}
	if info.Options["pinUvAuthToken"] {
		params = append(params, Pair{int64(2), int64(pinGetTokenPerm)}, Pair{int64(9), perms}, Pair{int64(10), rpID})
	} else {
		params = append(params, Pair{int64(2), int64(pinGetToken)})
	}
	m, err := c.call(cmdClientPIN, params)
	if err != nil {
		return nil, err
	}
	tokEnc, ok := bytesAt(m, int64(2))
	if !ok {
		return nil, ErrCBOR
	}
	return p.Decrypt(shared, tokEnc)
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func authData(ad []byte) (flags byte, credID []byte, ext map[any]any, err error) {
	if len(ad) < 37 {
		return 0, nil, nil, ErrCBOR
	}
	flags = ad[32]
	rest := ad[37:]
	if flags&0x40 != 0 {
		if len(rest) < 18 {
			return 0, nil, nil, ErrCBOR
		}
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		if len(rest) < 18+n {
			return 0, nil, nil, ErrCBOR
		}
		credID = rest[18 : 18+n]
		if _, rest, err = Decode(rest[18+n:]); err != nil {
			return 0, nil, nil, err
		}
	}
	if flags&0x80 != 0 {
		v, _, err := Decode(rest)
		if err != nil {
			return 0, nil, nil, err
		}
		ext, _ = asMap(v)
	}
	return flags, credID, ext, nil
}

func (c *Client) Register(rpID, pin string, exclude [][]byte) ([]byte, error) {
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	if !info.HasExtension("hmac-secret") {
		return nil, ErrNoHmacSecret
	}
	cdh := random(32)
	params := Map{
		{int64(1), cdh},
		{int64(2), Map{{"id", rpID}, {"name", "Sinty Key"}}},
		{int64(3), Map{{"id", random(16)}, {"name", "Sinty Key"}, {"displayName", "Sinty Key"}}},
		{int64(4), []any{Map{{"alg", int64(-7)}, {"type", "public-key"}}}},
		{int64(6), Map{{"hmac-secret", true}}},
		{int64(7), Map{{"rk", false}}},
	}
	if len(exclude) > 0 {
		list := make([]any, len(exclude))
		for i, id := range exclude {
			list[i] = Map{{"id", id}, {"type", "public-key"}}
		}
		params = append(params, Pair{int64(5), list})
	}
	if info.Options["clientPin"] {
		if pin == "" && !info.Options["makeCredUvNotRqd"] {
			return nil, ErrPINRequired
		}
		if pin != "" {
			p, err := c.protocol()
			if err != nil {
				return nil, err
			}
			tok, err := c.token(p, pin, rpID, permMakeCredential)
			if err != nil {
				return nil, err
			}
			params = append(params, Pair{int64(8), p.Authenticate(tok, cdh)}, Pair{int64(9), p.Version()})
		}
	}
	m, err := c.call(cmdMakeCredential, params)
	if err != nil {
		return nil, err
	}
	ad, ok := bytesAt(m, int64(2))
	if !ok {
		return nil, ErrCBOR
	}
	_, id, ext, err := authData(ad)
	if err != nil {
		return nil, err
	}
	if len(id) == 0 {
		return nil, ErrCBOR
	}
	if on, _ := ext["hmac-secret"].(bool); !on {
		return nil, ErrNoHmacSecret
	}
	return append([]byte(nil), id...), nil
}

func (c *Client) Secret(rpID string, ids [][]byte, salt []byte) ([]byte, []byte, error) {
	if len(salt) != 32 {
		return nil, nil, errors.New("fido2: the salt is 32 bytes")
	}
	if len(ids) == 0 {
		return nil, nil, ErrNoCredential
	}
	p, err := c.protocol()
	if err != nil {
		return nil, nil, err
	}
	ka, shared, err := c.keyAgreement(p)
	if err != nil {
		return nil, nil, err
	}
	saltEnc, err := p.Encrypt(shared, salt)
	if err != nil {
		return nil, nil, err
	}
	hs := Map{{int64(1), ka}, {int64(2), saltEnc}, {int64(3), p.Authenticate(shared, saltEnc)}}
	if p.Version() != 1 {
		hs = append(hs, Pair{int64(4), p.Version()})
	}
	allow := make([]any, 0, len(ids))
	for _, id := range ids {
		allow = append(allow, Map{{"id", id}, {"type", "public-key"}})
	}
	m, err := c.call(cmdGetAssertion, Map{
		{int64(1), rpID},
		{int64(2), random(32)},
		{int64(3), allow},
		{int64(4), Map{{"hmac-secret", hs}}},
		{int64(5), Map{{"up", true}}},
	})
	if err != nil {
		return nil, nil, err
	}
	ad, ok := bytesAt(m, int64(2))
	if !ok {
		return nil, nil, ErrCBOR
	}
	_, _, ext, err := authData(ad)
	if err != nil {
		return nil, nil, err
	}
	outEnc, ok := bytesAt(ext, "hmac-secret")
	if !ok {
		return nil, nil, ErrNoHmacSecret
	}
	out, err := p.Decrypt(shared, outEnc)
	if err != nil {
		return nil, nil, err
	}
	if len(out) < 32 {
		return nil, nil, ErrCBOR
	}
	used := ids[0]
	if cred, ok := asMap(m[int64(1)]); ok {
		if id, ok := bytesAt(cred, "id"); ok {
			used = id
		}
	}
	return used, out[:32], nil
}
