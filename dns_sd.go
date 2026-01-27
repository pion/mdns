// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// serviceTypeEnumerationName is the meta-query name for discovering all
// service types on the network (RFC 6763 §9).
// A PTR query for "_services._dns-sd._udp.<Domain>" yields PTR records
// whose rdata is the two-label <Service> name plus the domain.
const serviceTypeEnumerationName = "_services._dns-sd._udp"

// maxInstanceNameLen is the maximum length of a DNS label (RFC 1035 §2.3.4),
// which constrains the Instance portion of a Service Instance Name.
const maxInstanceNameLen = 63

var (
	errInvalidServiceName           = errors.New("mDNS: invalid DNS-SD service name")
	errInstanceNameTooLong          = errors.New("mDNS: service instance name exceeds 63 bytes")
	errInstanceNameEmpty            = errors.New("mDNS: service instance name must not be empty")
	errInstanceNameHasControl       = errors.New("mDNS: service instance name contains ASCII control character")
	errUnhandledServiceQuestionType = errors.New("mDNS: unhandled DNS-SD question type")
)

// ServiceInstance represents a DNS-SD service instance (RFC 6763).
//
// A service instance is identified by:
//
//	<Instance>.<Service>.<Domain>
//
// Example:
//
//	Instance: "My Web Server"
//	Service:  "_http._tcp"
//	Domain:   "local"
//	Host:     "myhost.local."
//	Port:     8080
type ServiceInstance struct {
	// Instance is the user-friendly name (UTF-8, max 63 bytes after encoding).
	// May contain dots and other punctuation (RFC 6763 §4.1.1).
	Instance string

	// Service is the service type, e.g. "_http._tcp".
	// Must be in the form "_<name>._<proto>" where proto is "tcp" or "udp".
	Service string

	// Domain is the DNS domain, typically "local" for mDNS.
	Domain string

	// Host is the target hostname for the SRV record (e.g. "myhost.local.").
	Host string

	// Port is the TCP or UDP port number.
	Port uint16

	// Priority is the SRV priority field (lower = preferred). Default 0.
	Priority uint16

	// Weight is the SRV weight field. Default 0.
	Weight uint16

	// Text contains the key/value pairs for the TXT record.
	Text []txtKeyValue
}

// serviceInstanceName returns the fully-qualified DNS name for this instance.
// Dots and backslashes in the Instance portion are escaped per RFC 6763 §4.3:
//   - Literal dots become "\."
//   - Literal backslashes become "\\"
//
// Example:
//
//	Instance="My.Web", Service="_http._tcp", Domain="local"
//	→ "My\.Web._http._tcp.local."
func (si *ServiceInstance) serviceInstanceName() string {
	escaped := escapeInstanceName(si.Instance)

	return escaped + "." + si.Service + "." + si.Domain + "."
}

// serviceName returns the <Service>.<Domain> browsing name
// (e.g. "_http._tcp.local.").
func (si *ServiceInstance) serviceName() string {
	return si.Service + "." + si.Domain + "."
}

// escapeInstanceName escapes dots and backslashes in an instance name
// for safe concatenation into a DNS name string (RFC 6763 §4.3).
func escapeInstanceName(instance string) string {
	// Fast path: no escaping needed
	if !strings.ContainsAny(instance, `.\`) {
		return instance
	}

	var buf strings.Builder
	buf.Grow(len(instance) + 4) // room for a few escapes
	for _, c := range instance {
		switch c {
		case '.':
			buf.WriteString(`\.`)
		case '\\':
			buf.WriteString(`\\`)
		default:
			buf.WriteRune(c)
		}
	}

	return buf.String()
}

// unescapeInstanceName reverses the escaping applied by escapeInstanceName.
// It converts "\." back to "." and "\\" back to "\".
func unescapeInstanceName(escaped string) string {
	if !strings.ContainsRune(escaped, '\\') {
		return escaped
	}

	var b strings.Builder
	b.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		switch {
		case escaped[i] == '\\' && i+1 < len(escaped):
			i++
			b.WriteByte(escaped[i])
		default:
			b.WriteByte(escaped[i])
		}
	}

	return b.String()
}

// parseServiceInstanceName splits a fully-qualified DNS name into its
// Instance, Service, and Domain components.
//
// The expected format is:
//
//	<Instance>.<_name>.<_proto>.<Domain>.
//
// Dots within the Instance portion must be escaped as "\." (RFC 6763 §4.3).
// The trailing dot is optional.
//
// Examples:
//
//	"My Web._http._tcp.local." → ("My Web", "_http._tcp", "local")
//	"My\.Web._http._tcp.local." → ("My.Web", "_http._tcp", "local")
func parseServiceInstanceName(name string) (instance, service, domain string, err error) {
	// Strip trailing dot
	name = strings.TrimSuffix(name, ".")

	// Split on unescaped dots. We need at least 4 labels:
	// <instance>, <_name>, <_proto>, <domain...>
	labels := splitEscapedDots(name)
	if len(labels) < 4 {
		return "", "", "", errInvalidServiceName
	}

	// The service is always the two labels starting with underscore.
	// Walk from position 1 to find _name._proto pattern.
	// The instance is everything before it, the domain is everything after.
	serviceIdx := -1
	for i := 1; i < len(labels)-1; i++ {
		if strings.HasPrefix(labels[i], "_") && strings.HasPrefix(labels[i+1], "_") {
			serviceIdx = i

			break
		}
	}
	if serviceIdx < 1 || serviceIdx+2 > len(labels) {
		return "", "", "", errInvalidServiceName
	}

	// Instance: rejoin labels before serviceIdx (unescaped)
	instanceParts := labels[:serviceIdx]
	instance = unescapeInstanceName(strings.Join(instanceParts, "."))

	service = labels[serviceIdx] + "." + labels[serviceIdx+1]
	domain = strings.Join(labels[serviceIdx+2:], ".")

	if instance == "" || service == "" || domain == "" {
		return "", "", "", errInvalidServiceName
	}

	return instance, service, domain, nil
}

// splitEscapedDots splits a string on dots that are NOT preceded by a backslash.
func splitEscapedDots(input string) []string {
	var labels []string
	var current strings.Builder

	for i := 0; i < len(input); i++ {
		switch {
		case input[i] == '\\' && i+1 < len(input):
			// Escaped character: keep both the backslash and the next char
			current.WriteByte(input[i])
			i++
			current.WriteByte(input[i])
		case input[i] == '.':
			labels = append(labels, current.String())
			current.Reset()
		default:
			current.WriteByte(input[i])
		}
	}
	labels = append(labels, current.String())

	return labels
}

// validateServiceName checks that a service string like "_http._tcp" follows
// the DNS-SD service naming rules (RFC 6763 §7, RFC 6335):
//   - Format: "_<name>._<proto>"
//   - Proto must be "_tcp" or "_udp"
//   - Name: 1-15 characters (not counting underscore prefix)
//   - Name: letters, digits, hyphens only
//   - Name: must begin and end with a letter or digit
//   - Name: must not contain consecutive hyphens
//   - Name: must contain at least one letter
func validateServiceName(service string) error {
	parts := strings.SplitN(service, ".", 2)
	if len(parts) != 2 {
		return errInvalidServiceName
	}

	namePart := parts[0]  // e.g. "_http"
	protoPart := parts[1] // e.g. "_tcp"

	if err := validateServiceProto(protoPart); err != nil {
		return err
	}

	return validateServiceLabel(namePart)
}

// validateServiceProto checks that the protocol label is "_tcp" or "_udp".
func validateServiceProto(proto string) error {
	if proto != "_tcp" && proto != "_udp" {
		return errInvalidServiceName
	}

	return nil
}

// validateServiceLabel checks the "_<name>" portion of a service name.
func validateServiceLabel(label string) error {
	if !strings.HasPrefix(label, "_") {
		return errInvalidServiceName
	}

	name := label[1:] // strip underscore prefix

	if len(name) == 0 || len(name) > 15 {
		return errInvalidServiceName
	}

	// Must begin and end with letter or digit
	if !isLetterOrDigit(name[0]) || !isLetterOrDigit(name[len(name)-1]) {
		return errInvalidServiceName
	}

	if err := validateServiceNameChars(name); err != nil {
		return err
	}

	return nil
}

// validateServiceNameChars checks individual characters in a service name:
// letters, digits, hyphens only; no consecutive hyphens; at least one letter.
func validateServiceNameChars(name string) error {
	hasLetter := false
	prevHyphen := false

	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case isLetter(c):
			hasLetter = true
			prevHyphen = false
		case isDigit(c):
			prevHyphen = false
		case c == '-':
			if prevHyphen {
				return errInvalidServiceName // consecutive hyphens
			}
			prevHyphen = true
		default:
			return errInvalidServiceName // invalid character
		}
	}

	if !hasLetter {
		return errInvalidServiceName
	}

	return nil
}

// validateInstanceName checks that an instance name is valid per RFC 6763 §4.1.1:
//   - Must not be empty
//   - Must not exceed 63 bytes when UTF-8 encoded
//   - Must not contain ASCII control characters (0x00-0x1F, 0x7F)
func validateInstanceName(instance string) error {
	if instance == "" {
		return errInstanceNameEmpty
	}

	if len(instance) > maxInstanceNameLen {
		return errInstanceNameTooLong
	}

	for i := 0; i < len(instance); i++ {
		b := instance[i]
		if b <= 0x1F || b == 0x7F {
			return errInstanceNameHasControl
		}
	}

	// Verify valid UTF-8
	if !utf8.ValidString(instance) {
		return errInstanceNameHasControl
	}

	return nil
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isLetterOrDigit(c byte) bool {
	return isLetter(c) || isDigit(c)
}
