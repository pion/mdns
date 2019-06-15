package mdns

import "errors"

var (
	errPacketTooSmall = errors.New("mDNS: packet is too small to be valid")
)
