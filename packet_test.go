package mdns

import (
	"reflect"
	"testing"
)

func TestPacket(t *testing.T) {
	dst := packet{}

	err := dst.Unmarshal([]byte{})
	if err == nil {
		t.Fatal("Packet was Unmarshaled that did not have a valid header")
	} else if err != errPacketTooSmall {
		t.Fatalf("Unexpected error (%v) expected (%v)", err, errPacketTooSmall)
	}

	emptyQueryRaw := []byte{0x00, 0x05, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	emptyQuery := packet{
		id:    0x005,
		flags: 0x8400,
	}

	if err = dst.Unmarshal(emptyQueryRaw); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(dst, emptyQuery) {
		t.Fatalf("packet unmarshal: got %#v, want %#v", dst, emptyQuery)
	}

	dstRaw, err := dst.Marshal()
	if err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(dstRaw, emptyQueryRaw) {
		t.Fatalf("packet unmarshal: got %#v, want %#v", dstRaw, emptyQueryRaw)
	}

}
