package mdns

import (
	"encoding/binary"
	"strings"
)

// Question is a mDNS question
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

const (
	questionTailLength = 4
)

func parseQName(data []byte) (string, error) {
	out := ""
	curLength := 0

	for i := 0; i < len(data); i++ {
		if curLength == 0 {
			curLength = int(data[i])
			continue
		}

		out += string(data[i])
		curLength--

		if curLength == 0 && i != len(data)-1 {
			out += "."
		}
	}

	if curLength != 0 {
		return "", errFailedParsingQName
	}
	return out, nil
}

// Marshal returns the encoded packet
func (q *Question) Marshal() ([]byte, error) {
	out := []byte{}
	split := strings.Split(q.Name, ".")

	for _, s := range split {
		out = append(out, byte(len(s)))
		out = append(out, []byte(s)...)
	}

	out = append(out, []byte{0x00, 0x00, 0x00, 0x00, 0x00}...)
	binary.BigEndian.PutUint16(out[len(out)-4:], q.Type)
	binary.BigEndian.PutUint16(out[len(out)-2:], q.Class)

	return out, nil
}

// Unmarshal parses the encoded data and stores the result in Question
func (q *Question) Unmarshal(data []byte) error {
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			if i+questionTailLength >= len(data) {
				return errPacketTooSmall
			}

			var err error
			q.Name, err = parseQName(data[:i])
			if err != nil {
				return err
			}
			q.Type = binary.BigEndian.Uint16(data[i+1:])
			q.Class = binary.BigEndian.Uint16(data[i+3:])
			return nil
		}
	}

	return errQuestionMissingTerminator
}

// Helper function that returns how long this packet would be if Marshaled
// useful when parsing multiple packets
func (q *Question) marshalLen() int {
	return 0
}
