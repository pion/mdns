package mdns

import (
	"encoding/binary"
	"math/big"
	"net"
	"strings"
)

// Answer is a mDNS answer
type Answer struct {
	Name       string
	Type       uint16
	Class      uint16
	CacheFlush bool
	TTL        uint32
	Address    net.IP
}

const (
	answerTailLength = 10
)

func ipToBytes(ip net.IP) []byte {
	rawIP := ip.To4()
	if rawIP == nil {
		return []byte{}
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	return ipInt.Bytes()

}

// Marshal returns the encoded packet
func (a *Answer) Marshal() ([]byte, error) {
	out := []byte{}
	split := strings.Split(a.Name, ".")

	for _, s := range split {
		out = append(out, byte(len(s)))
		out = append(out, []byte(s)...)
	}

	classAndCacheFlush := flags(a.Class)
	classAndCacheFlush.setIsCacheFlush(a.CacheFlush)

	// 1 for terminator, 4 for rData
	out = append(out, make([]byte, 1+answerTailLength)...)
	binary.BigEndian.PutUint16(out[len(out)-10:], a.Type)
	binary.BigEndian.PutUint16(out[len(out)-8:], uint16(classAndCacheFlush))
	binary.BigEndian.PutUint32(out[len(out)-6:], a.TTL)
	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(ipToBytes(a.Address))))
	out = append(out, ipToBytes(a.Address)...)
	return out, nil
}

// Unmarshal parses the encoded data and stores the result in Answer
func (a *Answer) Unmarshal(data []byte) error {
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			if i+answerTailLength >= len(data) {
				return errPacketTooSmall
			}

			var err error
			a.Name, err = parseQName(data[:i])
			if err != nil {
				return err
			}

			a.Type = binary.BigEndian.Uint16(data[i+1:])
			f := flags(binary.BigEndian.Uint16(data[i+3:]))

			a.CacheFlush = f.isCacheFlush()
			f.setIsCacheFlush(false)
			a.Class = uint16(f)

			a.TTL = binary.BigEndian.Uint32(data[i+5:])
			rDataLen := binary.BigEndian.Uint16(data[i+9:])
			if rDataLen == 4 && len(data) >= i+15 {
				address := data[i+11:]
				a.Address = net.IPv4(address[0], address[1], address[2], address[3])
			}
			return nil
		}
	}

	return errMissingTerminator
}

// nameLen + name + terminator + answerTailLength + IP Length
func (a *Answer) marshalLen() int {
	return 1 + len(a.Name) + 1 + answerTailLength + len(ipToBytes(a.Address))
}
