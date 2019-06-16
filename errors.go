package mdns

import "errors"

var (
	errPacketTooSmall = errors.New("mDNS: packet is too small to be valid")

	errQuestionMissingTerminator = errors.New("mDNS: Question is missing terminator")

	errFailedParsingQName = errors.New("mDNS: Failed to properly parse QNAME")
)
