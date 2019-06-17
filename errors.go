package mdns

import "errors"

var (
	errPacketTooSmall = errors.New("mDNS: packet is too small to be valid")

	errMissingTerminator = errors.New("mDNS: message is missing terminator")

	errFailedParsingQName = errors.New("mDNS: Failed to properly parse QNAME")
)
