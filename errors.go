package mdns

import "errors"

var (
	errJoiningMulticastGroup = errors.New("mDNS: failed to join multicast group")
)
