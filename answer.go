package mdns

// Answer is a mDNS answer
type Answer struct {
}

// Marshal returns the encoded packet
func (a *Answer) Marshal() ([]byte, error) {
	return []byte{}, nil
}

// Unmarshal parses the encoded data and stores the result in Answer
func (a *Answer) Unmarshal(data []byte) error {
	return nil
}

func (a *Answer) marshalLen() int {
	return 0
}
