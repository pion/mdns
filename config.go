// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"net"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	// DefaultAddressIPv4 is the default used by mDNS
	// and in most cases should be the address that the
	// ipv4.PacketConn passed to Server or NewServer is bound to.
	DefaultAddressIPv4 = "224.0.0.0:5353"

	// DefaultAddressIPv6 is the default IPv6 address used
	// by mDNS and in most cases should be the address that
	// the ipv6.PacketConn passed to Server or NewServer is bound to.
	DefaultAddressIPv6 = "[FF02::]:5353"
)

// Config is used to configure a mDNS client or server.
type Config struct {
	// Name is the name of the client/server used for logging purposes.
	Name string

	// QueryInterval controls how often we sends Queries until we
	// get a response for the requested name.
	QueryInterval time.Duration

	// LocalNames are the names that we will generate answers for
	// when we get questions.
	LocalNames []string

	// LocalAddress will override the published address with the given IP
	// when set. Otherwise, the automatically determined address will be used.
	LocalAddress net.IP

	// LoggerFactory is used to create a logger for the server.
	LoggerFactory logging.LoggerFactory

	// IncludeLoopback will include loopback interfaces to be eligible for queries and answers.
	IncludeLoopback bool

	// Interfaces will override the interfaces used for queries and answers.
	Interfaces []net.Interface
}

// ServerOption configures a Server.
type ServerOption interface {
	applyServer(*ServerConfig)
}

// ClientOption configures a Client.
type ClientOption interface {
	applyClient(*ClientConfig)
}

// ClientConfig holds configuration for a future dedicated Client type.
// Currently used to demonstrate shared options between Server and Client.
type ClientConfig struct {
	Name            string
	QueryInterval   time.Duration
	LoggerFactory   logging.LoggerFactory
	IncludeLoopback bool
	Interfaces      []net.Interface
}

// nameOption sets the name for logging.
type nameOption string

// WithName sets the name used for logging purposes.
func WithName(name string) nameOption {
	return nameOption(name)
}

func (o nameOption) applyServer(c *ServerConfig) { c.Name = string(o) }
func (o nameOption) applyClient(c *ClientConfig) { c.Name = string(o) }

// loggerFactoryOption sets the logger factory.
type loggerFactoryOption struct {
	factory logging.LoggerFactory
}

// WithLoggerFactory sets the logger factory for creating loggers.
func WithLoggerFactory(factory logging.LoggerFactory) loggerFactoryOption {
	return loggerFactoryOption{factory: factory}
}

func (o loggerFactoryOption) applyServer(c *ServerConfig) { c.LoggerFactory = o.factory }
func (o loggerFactoryOption) applyClient(c *ClientConfig) { c.LoggerFactory = o.factory }

// includeLoopbackOption sets whether to include loopback interfaces.
type includeLoopbackOption bool

// WithIncludeLoopback sets whether loopback interfaces should be included.
func WithIncludeLoopback(include bool) includeLoopbackOption {
	return includeLoopbackOption(include)
}

func (o includeLoopbackOption) applyServer(c *ServerConfig) { c.IncludeLoopback = bool(o) }
func (o includeLoopbackOption) applyClient(c *ClientConfig) { c.IncludeLoopback = bool(o) }

// interfacesOption sets the interfaces to use.
type interfacesOption []net.Interface

// WithInterfaces sets the network interfaces to use.
// If not set, all suitable interfaces will be discovered automatically.
func WithInterfaces(ifaces ...net.Interface) interfacesOption {
	return interfacesOption(ifaces)
}

func (o interfacesOption) applyServer(c *ServerConfig) { c.Interfaces = []net.Interface(o) }
func (o interfacesOption) applyClient(c *ClientConfig) { c.Interfaces = []net.Interface(o) }

// Server-only options

// localNamesOption sets the local names to respond to.
type localNamesOption []string

// WithLocalNames sets the names that the server will respond to.
// These are the mDNS names that this server will generate answers for.
func WithLocalNames(names ...string) localNamesOption {
	return localNamesOption(names)
}

func (o localNamesOption) applyServer(c *ServerConfig) { c.LocalNames = []string(o) }

// localAddressOption sets the local address to publish.
type localAddressOption struct {
	addr net.IP
}

// WithLocalAddress sets the IP address to publish in responses.
// If not set, the address will be automatically determined from the interface.
func WithLocalAddress(addr net.IP) localAddressOption {
	return localAddressOption{addr: addr}
}

func (o localAddressOption) applyServer(c *ServerConfig) { c.LocalAddress = o.addr }

// recordTypesOption limits which record types are processed.
type recordTypesOption []dnsmessage.Type

// WithRecordTypes limits which DNS record types the server will process.
// By default (if not called), all record types are allowed - no filtering.
//
// For WebRTC/ICE usage (legacy behavior), restrict to address records:
//
//	mdns.WithRecordTypes(dnsmessage.TypeA, dnsmessage.TypeAAAA)
func WithRecordTypes(types ...dnsmessage.Type) recordTypesOption {
	return recordTypesOption(types)
}

func (o recordTypesOption) applyServer(c *ServerConfig) {
	c.AllowedRecordTypes = []dnsmessage.Type(o)
}
