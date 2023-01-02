// Read / write softether packs

package main

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type valueType uint32

const (
	valueInt valueType = iota
	valueData
	valueString
	valueUniString
	valueInt64
)

const (
	maxPackSize = 10 * 1024
)

type packElement struct {
	valType valueType
	values  []any
}

type pack struct {
	elements map[string]packElement
}

func (p *pack) marshal() ([]byte, error) {
	var cb cryptobyte.Builder
	num := len(p.elements)
	cb.AddUint32(uint32(num))
	for key, element := range p.elements {
		b := []byte(key)
		cb.AddUint32(uint32(len(b)) + 1)
		cb.AddBytes(b)
		cb.AddUint32(uint32(element.valType))
		cb.AddUint32(uint32(len(element.values)))
		for _, v := range element.values {
			switch element.valType {
			case valueInt:
				cb.AddUint32(v.(uint32))
			case valueInt64:
				cb.AddUint64(v.(uint64))
			case valueData:
				cb.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(v.([]byte))
				})
			case valueString, valueUniString:
				cb.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(v.(string)))
				})
			}
		}
	}
	return cb.Bytes()
}

func (p *pack) unmarshal(data []byte) bool {
	cb := cryptobyte.String(data)
	var num uint32
	if !cb.ReadUint32(&num) {
		return false
	}
	p.elements = make(map[string]packElement)
	for i := 0; i < int(num); i++ {
		var n uint32
		if !cb.ReadUint32(&n) || n <= 1 || n > 64 {
			return false
		}
		var b []byte
		if !cb.ReadBytes(&b, int(n-1)) {
			return false
		}
		name := strings.ToLower(string(b))
		if !cb.ReadUint32(&n) {
			return false
		}
		element := packElement{valType: valueType(n)}
		if !cb.ReadUint32(&n) {
			return false
		}
		for j := 0; j < int(n); j++ {
			switch element.valType {
			case valueInt:
				var v uint32
				if !cb.ReadUint32(&v) {
					return false
				}
				element.values = append(element.values, v)
			case valueInt64:
				var v uint64
				if !cb.ReadUint64(&v) {
					return false
				}
				element.values = append(element.values, v)
			case valueData:
				var n uint32
				if !cb.ReadUint32(&n) {
					return false
				}
				var v []byte
				if !cb.ReadBytes(&v, int(n)) {
					return false
				}
				element.values = append(element.values, v)
			case valueString, valueUniString:
				var n uint32
				if !cb.ReadUint32(&n) {
					return false
				}
				var v []byte
				if !cb.ReadBytes(&v, int(n)) {
					return false
				}
				element.values = append(element.values, string(v))
			}
		}
		p.elements[name] = element
	}
	return true
}

func recvPack(conn io.Reader, hash bool) (pack, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil {
		return pack{}, err
	}
	n := binary.BigEndian.Uint32(b)
	if n > maxPackSize {
		return pack{}, errors.New("pack size too large")
	}
	b = make([]byte, n)
	if _, err := io.ReadFull(conn, b); err != nil {
		return pack{}, err
	}
	if hash {
		var h [20]byte
		if _, err := io.ReadFull(conn, h[:]); err != nil {
			return pack{}, err
		}
		if sha1.Sum(b) != h {
			return pack{}, errors.New("invalid checksum")
		}
	}
	var p pack
	if p.unmarshal(b) {
		return p, nil
	}
	return pack{}, errors.New("invalid pack")
}

func (p *pack) send(conn io.Writer, hash bool) (int, error) {
	var cb cryptobyte.Builder
	data, err := p.marshal()
	if err != nil {
		return 0, err
	}
	cb.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(data)
	})
	b, err := cb.Bytes()
	if err != nil {
		return 0, err
	}
	if hash {
		h := sha1.Sum(data)
		b = append(b, h[:]...)
	}
	return conn.Write(b)
}

func (p *pack) getInt(key string) (uint32, bool) {
	k := strings.ToLower(key)
	e, ok := p.elements[k]
	if !ok || e.valType != valueInt || len(e.values) == 0 {
		return 0, false
	}
	v, ok := e.values[0].(uint32)
	if !ok {
		return 0, false
	}
	return v, true
}

func (p *pack) getInt64(key string) (uint64, bool) {
	k := strings.ToLower(key)
	e, ok := p.elements[k]
	if !ok || e.valType != valueInt64 || len(e.values) == 0 {
		return 0, false
	}
	v, ok := e.values[0].(uint64)
	if !ok {
		return 0, false
	}
	return v, true
}

func (p *pack) getData(key string) ([]byte, bool) {
	k := strings.ToLower(key)
	e, ok := p.elements[k]
	if !ok || e.valType != valueData || len(e.values) == 0 {
		return nil, false
	}
	v, ok := e.values[0].([]byte)
	if !ok {
		return nil, false
	}
	return v, true
}

func (p *pack) getString(key string, lowercase bool) (string, bool) {
	k := strings.ToLower(key)
	e, ok := p.elements[k]
	if !ok || e.valType != valueString || len(e.values) == 0 {
		return "", false
	}
	v, ok := e.values[0].(string)
	if !ok {
		return "", false
	}
	if lowercase {
		v = strings.ToLower(v)
	}
	return v, true
}

func newPackElementInt(n uint32) packElement {
	e := packElement{valType: valueInt}
	e.values = append(e.values, n)
	return e
}

func newPackElementInt64(n uint64) packElement {
	e := packElement{valType: valueInt64}
	e.values = append(e.values, n)
	return e
}

func newPackElementData(b []byte) packElement {
	e := packElement{valType: valueData}
	e.values = append(e.values, b)
	return e
}

func newPackElementString(s string) packElement {
	e := packElement{valType: valueString}
	e.values = append(e.values, s)
	return e
}

func (p *pack) addIP(field string, ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		p.elements[field+"@ipv6_bool"] = newPackElementInt(0)
		p.elements[field+"@ipv6_array"] = newPackElementData(net.IPv6zero)
		p.elements[field+"@ipv6_scope_id"] = newPackElementInt(0)
		p.elements[field] = newPackElementInt(ip4ToUInt32(ip4))
	} else {
		p.elements[field+"@ipv6_bool"] = newPackElementInt(1)
		p.elements[field+"@ipv6_array"] = newPackElementData(ip)
		p.elements[field+"@ipv6_scope_id"] = newPackElementInt(0)
		p.elements[field] = newPackElementInt(0)
	}
}

// Convert IPv4 address to uint32 in little endian
func ip4ToUInt32(ip net.IP) uint32 {
	if len(ip) != net.IPv4len {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}
