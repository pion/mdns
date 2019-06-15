package mdns

import "encoding/binary"

// packet is the toplevel container for all mDNS communication
type packet struct {
	id    uint16
	flags flags
	// questions []Question
	// answers   []Answer
}

const (
	packetHeaderLen = 12
)

func (p *packet) Marshal() ([]byte, error) {
	out := make([]byte, packetHeaderLen)
	binary.BigEndian.PutUint16(out, p.id)
	binary.BigEndian.PutUint16(out[2:], uint16(p.flags))

	return out, nil
}

func (p *packet) Unmarshal(data []byte) error {
	if len(data) < packetHeaderLen {
		return errPacketTooSmall
	}
	p.id = binary.BigEndian.Uint16(data)
	p.flags = flags(binary.BigEndian.Uint16(data[2:]))

	return nil
}
