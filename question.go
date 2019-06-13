package mdns

// Question is a mDNS question
type Question struct {
}

// Marshal returns the encoded packet
func (q *Question) Marshal() ([]byte, error) {
	return []byte{}, nil
}

// Unmarshal parses the encoded data and stores the result in Question
func (q *Question) Unmarshal(data []byte) error {
	return nil
}
