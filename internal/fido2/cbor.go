package fido2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

var ErrCBOR = errors.New("malformed CBOR")

type Pair struct {
	Key   any
	Value any
}

type Map []Pair

func head(buf *bytes.Buffer, major byte, n uint64) {
	switch {
	case n < 24:
		buf.WriteByte(major<<5 | byte(n))
	case n <= 0xff:
		buf.WriteByte(major<<5 | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(major<<5 | 25)
		binary.Write(buf, binary.BigEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(major<<5 | 26)
		binary.Write(buf, binary.BigEndian, uint32(n))
	default:
		buf.WriteByte(major<<5 | 27)
		binary.Write(buf, binary.BigEndian, n)
	}
}

func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteByte(0xf6)
	case bool:
		if x {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case int:
		return encode(buf, int64(x))
	case int64:
		if x >= 0 {
			head(buf, 0, uint64(x))
		} else {
			head(buf, 1, uint64(-1-x))
		}
	case uint64:
		head(buf, 0, x)
	case []byte:
		head(buf, 2, uint64(len(x)))
		buf.Write(x)
	case string:
		head(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []any:
		head(buf, 4, uint64(len(x)))
		for _, e := range x {
			if err := encode(buf, e); err != nil {
				return err
			}
		}
	case Map:
		type kv struct{ k, v []byte }
		items := make([]kv, 0, len(x))
		for _, p := range x {
			k, err := Encode(p.Key)
			if err != nil {
				return err
			}
			val, err := Encode(p.Value)
			if err != nil {
				return err
			}
			items = append(items, kv{k, val})
		}
		sort.Slice(items, func(i, j int) bool {
			if len(items[i].k) != len(items[j].k) {
				return len(items[i].k) < len(items[j].k)
			}
			return bytes.Compare(items[i].k, items[j].k) < 0
		})
		head(buf, 5, uint64(len(items)))
		for _, it := range items {
			buf.Write(it.k)
			buf.Write(it.v)
		}
	default:
		return fmt.Errorf("cbor: cannot encode %T", v)
	}
	return nil
}

func Decode(data []byte) (any, []byte, error) {
	return decode(data, 0)
}

func decode(data []byte, depth int) (any, []byte, error) {
	if depth > 16 || len(data) == 0 {
		return nil, nil, ErrCBOR
	}
	major, info := data[0]>>5, data[0]&0x1f
	data = data[1:]
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info == 24 && len(data) >= 1:
		n, data = uint64(data[0]), data[1:]
	case info == 25 && len(data) >= 2:
		n, data = uint64(binary.BigEndian.Uint16(data)), data[2:]
	case info == 26 && len(data) >= 4:
		n, data = uint64(binary.BigEndian.Uint32(data)), data[4:]
	case info == 27 && len(data) >= 8:
		n, data = binary.BigEndian.Uint64(data), data[8:]
	default:
		return nil, nil, ErrCBOR
	}
	switch major {
	case 0:
		if n > 1<<62 {
			return nil, nil, ErrCBOR
		}
		return int64(n), data, nil
	case 1:
		if n > 1<<62 {
			return nil, nil, ErrCBOR
		}
		return -1 - int64(n), data, nil
	case 2, 3:
		if n > uint64(len(data)) {
			return nil, nil, ErrCBOR
		}
		if major == 2 {
			return append([]byte(nil), data[:n]...), data[n:], nil
		}
		return string(data[:n]), data[n:], nil
	case 4:
		if n > uint64(len(data)) {
			return nil, nil, ErrCBOR
		}
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			var v any
			var err error
			if v, data, err = decode(data, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, data, nil
	case 5:
		if n > uint64(len(data)) {
			return nil, nil, ErrCBOR
		}
		out := make(map[any]any, n)
		for i := uint64(0); i < n; i++ {
			var k, v any
			var err error
			if k, data, err = decode(data, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, ErrCBOR
			}
			if v, data, err = decode(data, depth+1); err != nil {
				return nil, nil, err
			}
			out[k] = v
		}
		return out, data, nil
	case 7:
		switch info {
		case 20:
			return false, data, nil
		case 21:
			return true, data, nil
		case 22, 23:
			return nil, data, nil
		}
	}
	return nil, nil, ErrCBOR
}

func asMap(v any) (map[any]any, bool) {
	m, ok := v.(map[any]any)
	return m, ok
}

func intKey(m map[any]any, k int64) any {
	return m[k]
}

func bytesAt(m map[any]any, k any) ([]byte, bool) {
	b, ok := m[k].([]byte)
	return b, ok
}
