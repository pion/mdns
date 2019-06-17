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
			name:               "Empty Query Response",
			raw:                []byte{0x00, 0x05, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			pkt:                packet{id: 0x005, flags: 0x8400},
			expectedMarshalErr: nil,
		},
		{
			name: "One Question",
			raw: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x5f, 0x63, 0x6f,
				0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69, 0x6e, 0x6b, 0x04, 0x5f, 0x74, 0x63,
				0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x80, 0x01,
			},
			pkt: packet{
				questions: []*Question{
					{"_companion-link._tcp.local", 0xc, 0x8001},
				},
			},
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
