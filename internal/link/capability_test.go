package link

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestCapabilityEncoding(t *testing.T) {
	got, err := EncodeCapability(Capability{Version: CapabilityVersion, Bits: RequiredCapabilityMask})
	if err != nil {
		t.Fatal(err)
	}
	// Frozen wire vector: the literal version byte must stay 2 regardless of the
	// CapabilityVersion constant so a schema bump still fails this test.
	want := []byte{2, 0, 0, 0, 0, 0, 0, 0, 0x7f}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeCapability() = %x; want %x", got, want)
	}
	decoded, err := DecodeCapability(want)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Version != CapabilityVersion || decoded.Bits != RequiredCapabilityMask {
		t.Fatalf("DecodeCapability() = %#v", decoded)
	}
	got[8] = 0
	decoded, err = DecodeCapability(want)
	if err != nil || decoded.Bits != RequiredCapabilityMask {
		t.Fatalf("encoding mutation affected input or decode: %#v, %v", decoded, err)
	}
}

func TestCapabilityEncodingRejectsInvalidValues(t *testing.T) {
	for _, test := range []struct {
		name string
		cap  Capability
		err  error
	}{
		{"version", Capability{Version: 1, Bits: RequiredCapabilityMask}, ErrCapabilityVersion},
		{"missing required bit", Capability{Version: CapabilityVersion, Bits: RequiredCapabilityMask &^ 1}, ErrCapabilityBits},
		{"reserved bit", Capability{Version: CapabilityVersion, Bits: RequiredCapabilityMask | 1<<7}, ErrCapabilityBits},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := EncodeCapability(test.cap)
			if !errors.Is(err, test.err) {
				t.Fatalf("EncodeCapability() error = %v; want %v", err, test.err)
			}
		})
	}
}

func TestCapabilityDecodingRejectsInvalidPayloads(t *testing.T) {
	valid := []byte{2, 0, 0, 0, 0, 0, 0, 0, 0x7f}
	cases := []struct {
		name string
		data []byte
		err  error
	}{
		{"short", valid[:8], ErrCapabilityMalformed},
		{"long", append(append([]byte(nil), valid...), 0), ErrCapabilityMalformed},
		{"version", append([]byte{1}, valid[1:]...), ErrCapabilityVersion},
		{"missing required bit", append([]byte{CapabilityVersion}, make([]byte, 8)...), ErrCapabilityBits},
		{"reserved bit", func() []byte {
			data := append([]byte(nil), valid...)
			binary.BigEndian.PutUint64(data[1:], RequiredCapabilityMask|1<<63)
			return data
		}(), ErrCapabilityBits},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeCapability(test.data)
			if !errors.Is(err, test.err) {
				t.Fatalf("DecodeCapability() error = %v; want %v", err, test.err)
			}
		})
	}
}
