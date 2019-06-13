package mdns

// packet is the toplevel container for all mDNS communication
type packet struct {
	// id        uint16
	// flags     flags
	// questions []Question
	// answers   []Answer
}

func (p *packet) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (p *packet) Unmarshal(data []byte) error {
	return nil
}
