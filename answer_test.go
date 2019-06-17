package mdns

import (
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnswer(t *testing.T) {
	simpleAnswerRaw := []byte{
		0x24, 0x61, 0x32, 0x35, 0x30, 0x64, 0x39, 0x36, 0x62, 0x2d, 0x32, 0x38, 0x34, 0x62, 0x2d, 0x34,
		0x66, 0x63, 0x64, 0x2d, 0x61, 0x34, 0x36, 0x35, 0x2d, 0x36, 0x39, 0x32, 0x39, 0x31, 0x34, 0x32,
		0x35, 0x63, 0x31, 0x31, 0x61, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x80, 0x01,
		0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8, 0x01, 0x0a,
	}
	simpleAnswer := Answer{
		Name:       "a250d96b-284b-4fcd-a465-69291425c11a.local",
		Type:       1,
		Class:      1,
		CacheFlush: true,
		TTL:        120,
		Address:    net.ParseIP("192.168.1.10"),
	}

	dst := Answer{}
	if err := dst.Unmarshal(simpleAnswerRaw); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(dst, simpleAnswer) {
		t.Fatalf("Unmarshal: got %#v, want %#v", dst, simpleAnswer)
	}

	dstRaw, err := simpleAnswer.Marshal()
	switch {
	case err != nil:
		t.Fatal(err)
	case !reflect.DeepEqual(dstRaw, simpleAnswerRaw):
		assert.Equal(t, dstRaw, simpleAnswerRaw)
		t.Fatalf("Marshal: got %#v, want %#v", dstRaw, simpleAnswerRaw)
	case len(dstRaw) != simpleAnswer.marshalLen():
		t.Fatalf("Marshal != marshalLen: got %#v, want %#v", len(dstRaw), simpleAnswer.marshalLen())
	}
}
