package mdns

type flags uint16

const (
	isQueryResponseMask            = 0x8000
	isAuthoritativeOrTruncatedMask = 0x400
	isCacheFlush                   = 0x8000

	maxUint16 = ^uint16(0)
)

func isFlagSet(f uint16, mask uint16) bool {
	return (f &^ (maxUint16 ^ mask)) == mask
}

func toggleFlag(f uint16, enable bool, mask uint16) uint16 {
	if enable {
		return f | mask
	}
	return f &^ mask
}

func (f flags) isQueryResponse() bool {
	return isFlagSet(uint16(f), isQueryResponseMask)
}
func (f *flags) setIsQueryResponse(t bool) {
	*f = flags(toggleFlag(uint16(*f), t, isQueryResponseMask))
}

// If flag is for a query this determines if it is truncated
// If flag is for a response this determines if it is authoritative
func (f flags) isAuthoritativeOrTruncated() bool {
	return isFlagSet(uint16(f), isAuthoritativeOrTruncatedMask)
}
func (f *flags) setIsAuthoritativeOrTruncated(t bool) {
	*f = flags(toggleFlag(uint16(*f), t, isAuthoritativeOrTruncatedMask))
}

func (f flags) isCacheFlush() bool {
	return isFlagSet(uint16(f), isCacheFlush)
}
func (f *flags) setIsCacheFlush(t bool) {
	*f = flags(toggleFlag(uint16(*f), t, isCacheFlush))
}
