package mdns

import (
	"encoding/binary"
)

// packet is the toplevel container for all mDNS communication
type packet struct {
	id        uint16
	flags     flags
	questions []*Question
	answers   []*Answer
}

type packetMember interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	marshalLen() int
}

const (
	packetHeaderLen = 12
)

func (p *packet) Marshal() ([]byte, error) {
	out := make([]byte, packetHeaderLen)
	binary.BigEndian.PutUint16(out, p.id)
	binary.BigEndian.PutUint16(out[2:], uint16(p.flags))
	binary.BigEndian.PutUint16(out[4:], uint16(len(p.questions)))
	binary.BigEndian.PutUint16(out[6:], uint16(len(p.answers)))

	addPacketMember := func(m packetMember) error {
		raw, err := m.Marshal()
		if err != nil {
			return err
		}
		out = append(out, raw...)
		return nil
	}

	for _, q := range p.questions {
		if err := addPacketMember(q); err != nil {
			return nil, err
		}
	}
	for _, a := range p.answers {
		if err := addPacketMember(a); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func (p *packet) Unmarshal(data []byte) error {
	if len(data) < packetHeaderLen {
		return errPacketHeaderTooSmall
	}

	p.questions = p.questions[:0]
	p.answers = p.answers[:0]

	p.id = binary.BigEndian.Uint16(data)
	p.flags = flags(binary.BigEndian.Uint16(data[2:]))

	questions := binary.BigEndian.Uint16(data[4:])
	for ; questions > 0; questions-- {
		p.questions = append(p.questions, &Question{})
	}

	answers := binary.BigEndian.Uint16(data[6:])
	for ; answers > 0; answers-- {
		p.answers = append(p.answers, &Answer{})
	}

	offset := packetHeaderLen
	unmarshalMember := func(m packetMember) error {
		if offset >= len(data) {
			return errPacketMemberTooSmall
		}

		if err := m.Unmarshal(data[offset:]); err != nil {
			return err
		}
		offset += m.marshalLen()
		return nil
	}

	for _, q := range p.questions {
		if err := unmarshalMember(q); err != nil {
			return err
		}
	}
	for _, a := range p.answers {
		if err := unmarshalMember(a); err != nil {
			return err
		}
	}

	return nil
}
