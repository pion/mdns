package mdns

import (
	"reflect"
	"testing"
)

func TestPacket(t *testing.T) {
	for _, test := range []struct {
		name               string
		raw                []byte
		pkt                packet
		expectedMarshalErr error
	}{
		{
			name:               "Invalid Packet",
			raw:                []byte{},
			pkt:                packet{},
			expectedMarshalErr: errPacketTooSmall,
		},
		{
			name:               "Empty Query",
			raw:                []byte{0x00, 0x05, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			pkt:                packet{id: 0x005, flags: 0x8400},
			expectedMarshalErr: nil,
		},
	} {
		dst := packet{}
		err := dst.Unmarshal(test.raw)
		if err != test.expectedMarshalErr {
			t.Fatalf("Unexpected error (%v) expected (%v)", err, test.expectedMarshalErr)
		}
		if test.expectedMarshalErr != nil {
			continue // Only do equality checks in non-err case
		}

		dstRaw, _ := dst.Marshal()
		if !reflect.DeepEqual(dst, test.pkt) {
			t.Fatalf("%s Unmarshal: got %#v, want %#v", test.name, dst, test.pkt)
		} else if !reflect.DeepEqual(dstRaw, test.raw) {
			t.Fatalf("%s Marshal: got %#v, want %#v", test.name, dstRaw, test.raw)
		}
	}
}
