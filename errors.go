package mdns

import "errors"

var (
	errJoiningMulticastGroup = errors.New("mDNS: failed to join multicast group")

	errPacketHeaderTooSmall   = errors.New("mDNS: packet is too small to be contain valid header")
	errPacketMemberTooSmall   = errors.New("mDNS: packet is too small to be contain valid member")
	errQuestionHeaderTooSmall = errors.New("mDNS: question is too small to be contain valid header")
	errAnswerHeaderTooSmall   = errors.New("mDNS: answer is too small to be contain valid header")

	errMissingTerminator = errors.New("mDNS: message is missing terminator")

	errFailedParsingQName = errors.New("mDNS: Failed to parse QNAME")
)
