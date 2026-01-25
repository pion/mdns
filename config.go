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
	applyServer(*serverConfig) error
}

// ClientOption configures a Client.
type ClientOption interface {
	applyClient(*clientConfig) error
}

// clientConfig holds configuration for a future dedicated Client type.
// Currently used to demonstrate shared options between Server and Client.
type clientConfig struct {
	name            string
	queryInterval   time.Duration
	loggerFactory   logging.LoggerFactory
	includeLoopback bool
	interfaces      []net.Interface
}

// nameOption sets the name for logging.
type nameOption string

// WithName sets the name used for logging purposes.
func WithName(name string) nameOption {
	return nameOption(name)
}

func (o nameOption) applyServer(c *serverConfig) error {
	c.name = string(o)

	return nil
}

func (o nameOption) applyClient(c *clientConfig) error {
	c.name = string(o)

	return nil
}

// loggerFactoryOption sets the logger factory.
type loggerFactoryOption struct {
	factory logging.LoggerFactory
}

// WithLoggerFactory sets the logger factory for creating loggers.
func WithLoggerFactory(factory logging.LoggerFactory) loggerFactoryOption {
	return loggerFactoryOption{factory: factory}
}

func (o loggerFactoryOption) applyServer(c *serverConfig) error {
	c.loggerFactory = o.factory

	return nil
}

func (o loggerFactoryOption) applyClient(c *clientConfig) error {
	c.loggerFactory = o.factory

	return nil
}

// includeLoopbackOption sets whether to include loopback interfaces.
type includeLoopbackOption bool

// WithIncludeLoopback sets whether loopback interfaces should be included.
func WithIncludeLoopback(include bool) includeLoopbackOption {
	return includeLoopbackOption(include)
}

func (o includeLoopbackOption) applyServer(c *serverConfig) error {
	c.includeLoopback = bool(o)

	return nil
}

func (o includeLoopbackOption) applyClient(c *clientConfig) error {
	c.includeLoopback = bool(o)

	return nil
}

// interfacesOption sets the interfaces to use.
type interfacesOption []net.Interface

// WithInterfaces sets the network interfaces to use.
// If not set, all suitable interfaces will be discovered automatically.
func WithInterfaces(ifaces ...net.Interface) interfacesOption {
	return interfacesOption(ifaces)
}

func (o interfacesOption) applyServer(c *serverConfig) error {
	c.interfaces = []net.Interface(o)

	return nil
}

func (o interfacesOption) applyClient(c *clientConfig) error {
	c.interfaces = []net.Interface(o)

	return nil
}

// Server-only options

// localNamesOption sets the local names to respond to.
type localNamesOption []string

// WithLocalNames sets the names that the server will respond to.
// These are the mDNS names that this server will generate answers for.
func WithLocalNames(names ...string) localNamesOption {
	return localNamesOption(names)
}

func (o localNamesOption) applyServer(c *serverConfig) error {
	c.localNames = []string(o)

	return nil
}

// localAddressOption sets the local address to publish.
type localAddressOption struct {
	addr net.IP
}

// WithLocalAddress sets the IP address to publish in responses.
// If not set, the address will be automatically determined from the interface.
func WithLocalAddress(addr net.IP) localAddressOption {
	return localAddressOption{addr: addr}
}

func (o localAddressOption) applyServer(c *serverConfig) error {
	c.localAddress = o.addr

	return nil
}

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

func (o recordTypesOption) applyServer(c *serverConfig) error {
	c.allowedRecordTypes = []dnsmessage.Type(o)

	return nil
}

// responseTTLOption sets the TTL for DNS responses.
type responseTTLOption uint32

// WithResponseTTL sets the TTL (in seconds) for DNS response records.
// Default is 120 seconds per RFC 6762 recommendation.
func WithResponseTTL(seconds uint32) responseTTLOption {
	return responseTTLOption(seconds)
}

func (o responseTTLOption) applyServer(c *serverConfig) error {
	c.responseTTL = uint32(o)

	return nil
}
