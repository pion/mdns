package mdns

import (
	"reflect"
	"testing"
)

func TestQuestion(t *testing.T) {
	simpleQuestionRaw := []byte{
		0x0f, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69,
		0x6e, 0x6b, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
		0x00, 0x0c, 0x00, 0x01,
	}
	simpleQuestion := Question{
		Name:  "_companion-link._tcp.local",
		Type:  0x000c,
		Class: 0x0001,
	}

	dst := Question{}
	if err := dst.Unmarshal(simpleQuestionRaw); err != nil {
		t.Fatal(err)
	} else if !reflect.DeepEqual(dst, simpleQuestion) {
		t.Fatalf("Unmarshal: got %#v, want %#v", dst, simpleQuestion)
	}

	dstRaw, err := simpleQuestion.Marshal()
	switch {
	case err != nil:
		t.Fatal(err)
	case !reflect.DeepEqual(dstRaw, simpleQuestionRaw):
		t.Fatalf("Marshal: got %#v, want %#v", dstRaw, simpleQuestionRaw)
	case len(dstRaw) != simpleQuestion.marshalLen():
		t.Fatalf("Marshal != marshalLen: got %#v, want %#v", len(dstRaw), simpleQuestion.marshalLen())
	}
}

func TestQuestionErr(t *testing.T) {
	dst := Question{}
	if err := dst.Unmarshal([]byte{0xFF, 0x00, 0x00, 0x0c, 0x00, 0x01}); err != errFailedParsingQName {
		t.Fatalf("Unexpected Error: expected(%v) actual(%v) ", errFailedParsingQName, err)
	}

	if err := dst.Unmarshal([]byte{0xFF, 0x00, 0x00, 0x0c, 0x00}); err != errPacketTooSmall {
		t.Fatalf("Unexpected Error: expected(%v) actual(%v) ", errPacketTooSmall, err)
	}

	if err := dst.Unmarshal([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}); err != errMissingTerminator {
		t.Fatalf("Unexpected Error: expected(%v) actual(%v) ", errMissingTerminator, err)
	}
}
