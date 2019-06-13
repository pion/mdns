package mdns

import "time"

const (
	// DefaultAddress is the default used by mDNS
	// and in most cases should be the address that the
	// net.Conn passed to Server is bound to
	DefaultAddress = "224.0.0.251:5353"
)

// Config is used to configure a mDNS client or server.
type Config struct {
	// QueryInterval controls how ofter we sends Queries until we
	// get a response for the requested name
	QueryInterval time.Duration
}
