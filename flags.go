package mdns

type flags uint16

const (
	isQueryResponseMask            = 0x8000
	isAuthoritativeOrTruncatedMask = 0x400

	maxUint16 = ^uint16(0)
)

func isFlagSet(f uint16, mask uint16) bool {
	return (f &^ (maxUint16 ^ mask)) == mask
}

func (f flags) isQueryResponse() bool {
	return isFlagSet(uint16(f), isQueryResponseMask)
}
func (f *flags) setIsQueryResponse(t bool) {
	if t {
		*f |= isQueryResponseMask
	} else {
		*f &^= isQueryResponseMask
	}
}

// If flag is for a query this determines if it is truncated
// If flag is for a response this determines if it is authoritative
func (f flags) isAuthoritativeOrTruncated() bool {
	return isFlagSet(uint16(f), isAuthoritativeOrTruncatedMask)
}
func (f *flags) setIsAuthoritativeOrTruncated(t bool) {
	if t {
		*f |= isAuthoritativeOrTruncatedMask
	} else {
		*f &^= isAuthoritativeOrTruncatedMask
	}
}
