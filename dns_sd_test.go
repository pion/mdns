// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ServiceInstance — name construction
// ---------------------------------------------------------------------------

func TestServiceInstanceName_Simple(t *testing.T) {
	si := ServiceInstance{
		Instance: "My Web Server",
		Service:  "_http._tcp",
		Domain:   "local",
	}
	assert.Equal(t, "My Web Server._http._tcp.local.", si.serviceInstanceName())
}

func TestServiceInstanceName_DotsEscaped(t *testing.T) {
	// RFC 6763 §4.3: dots in Instance escaped as "\."
	si := ServiceInstance{
		Instance: "My.Web",
		Service:  "_http._tcp",
		Domain:   "local",
	}
	assert.Equal(t, `My\.Web._http._tcp.local.`, si.serviceInstanceName())
}

func TestServiceInstanceName_BackslashEscaped(t *testing.T) {
	// RFC 6763 §4.3: backslashes in Instance escaped as "\\"
	si := ServiceInstance{
		Instance: `Back\slash`,
		Service:  "_http._tcp",
		Domain:   "local",
	}
	assert.Equal(t, `Back\\slash._http._tcp.local.`, si.serviceInstanceName())
}

func TestServiceInstanceName_DotAndBackslash(t *testing.T) {
	si := ServiceInstance{
		Instance: `Dot.And\Slash`,
		Service:  "_http._tcp",
		Domain:   "local",
	}
	assert.Equal(t, `Dot\.And\\Slash._http._tcp.local.`, si.serviceInstanceName())
}

func TestServiceInstanceName_NoSpecialChars(t *testing.T) {
	si := ServiceInstance{
		Instance: "No Special Chars",
		Service:  "_http._tcp",
		Domain:   "local",
	}
	assert.Equal(t, "No Special Chars._http._tcp.local.", si.serviceInstanceName())
}

func TestServiceInstanceName_RFC6763_Section13(t *testing.T) {
	// Test vectors from RFC 6763 §13.1
	tests := []struct {
		instance string
		service  string
		domain   string
		expected string
	}{
		{"Zeroconf", "_http._tcp", "dns-sd.org", "Zeroconf._http._tcp.dns-sd.org."},
		{"Multicast DNS", "_http._tcp", "dns-sd.org", "Multicast DNS._http._tcp.dns-sd.org."},
		{"Service Discovery", "_http._tcp", "dns-sd.org", "Service Discovery._http._tcp.dns-sd.org."},
		{"Stuart's Printer", "_http._tcp", "dns-sd.org", "Stuart's Printer._http._tcp.dns-sd.org."},
	}
	for _, tc := range tests {
		si := ServiceInstance{Instance: tc.instance, Service: tc.service, Domain: tc.domain}
		assert.Equal(t, tc.expected, si.serviceInstanceName(), "instance=%q", tc.instance)
	}
}

// ---------------------------------------------------------------------------
// ServiceInstance — serviceName
// ---------------------------------------------------------------------------

func TestServiceName(t *testing.T) {
	si := ServiceInstance{
		Service: "_http._tcp",
		Domain:  "local",
	}
	assert.Equal(t, "_http._tcp.local.", si.serviceName())
}

// ---------------------------------------------------------------------------
// escapeInstanceName / unescapeInstanceName round-trip
// ---------------------------------------------------------------------------

func TestEscapeUnescapeRoundTrip(t *testing.T) {
	tests := []string{
		"simple",
		"has.dot",
		`has\backslash`,
		`dot.and\slash`,
		"no escaping needed",
		`multi.ple.dots`,
		`back\\slash`,
	}
	for _, input := range tests {
		escaped := escapeInstanceName(input)
		unescaped := unescapeInstanceName(escaped)
		assert.Equal(t, input, unescaped, "round-trip failed for %q", input)
	}
}

func TestEscapeInstanceName_NothingToEscape(t *testing.T) {
	assert.Equal(t, "hello world", escapeInstanceName("hello world"))
}

func TestEscapeInstanceName_Dots(t *testing.T) {
	assert.Equal(t, `a\.b\.c`, escapeInstanceName("a.b.c"))
}

func TestEscapeInstanceName_Backslashes(t *testing.T) {
	assert.Equal(t, `a\\b`, escapeInstanceName(`a\b`))
}

// ---------------------------------------------------------------------------
// parseServiceInstanceName
// ---------------------------------------------------------------------------

func TestParseServiceInstanceName_Simple(t *testing.T) {
	inst, svc, dom, err := parseServiceInstanceName("My Web._http._tcp.local.")
	require.NoError(t, err)
	assert.Equal(t, "My Web", inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "local", dom)
}

func TestParseServiceInstanceName_EscapedDot(t *testing.T) {
	// From test_vectors.md §8
	inst, svc, dom, err := parseServiceInstanceName(`My\.Web._http._tcp.local.`)
	require.NoError(t, err)
	assert.Equal(t, "My.Web", inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "local", dom)
}

func TestParseServiceInstanceName_EscapedBackslash(t *testing.T) {
	// From test_vectors.md §8
	inst, svc, dom, err := parseServiceInstanceName(`Back\\slash._http._tcp.local.`)
	require.NoError(t, err)
	assert.Equal(t, `Back\slash`, inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "local", dom)
}

func TestParseServiceInstanceName_DotAndBackslash(t *testing.T) {
	inst, svc, dom, err := parseServiceInstanceName(`Dot\.And\\Slash._http._tcp.local.`)
	require.NoError(t, err)
	assert.Equal(t, `Dot.And\Slash`, inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "local", dom)
}

func TestParseServiceInstanceName_NoTrailingDot(t *testing.T) {
	inst, svc, dom, err := parseServiceInstanceName("My Web._http._tcp.local")
	require.NoError(t, err)
	assert.Equal(t, "My Web", inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "local", dom)
}

func TestParseServiceInstanceName_MultiLabelDomain(t *testing.T) {
	inst, svc, dom, err := parseServiceInstanceName("Zeroconf._http._tcp.dns-sd.org.")
	require.NoError(t, err)
	assert.Equal(t, "Zeroconf", inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "dns-sd.org", dom)
}

func TestParseServiceInstanceName_SpaceInInstance(t *testing.T) {
	inst, svc, dom, err := parseServiceInstanceName("Service Discovery._http._tcp.dns-sd.org.")
	require.NoError(t, err)
	assert.Equal(t, "Service Discovery", inst)
	assert.Equal(t, "_http._tcp", svc)
	assert.Equal(t, "dns-sd.org", dom)
}

func TestParseServiceInstanceName_TooFewLabels(t *testing.T) {
	_, _, _, err := parseServiceInstanceName("_http._tcp.") //nolint:dogsled
	assert.Error(t, err)
}

func TestParseServiceInstanceName_NoUnderscoreLabels(t *testing.T) {
	_, _, _, err := parseServiceInstanceName("a.b.c.d.") //nolint:dogsled
	assert.Error(t, err)
}

func TestParseServiceInstanceName_Empty(t *testing.T) {
	_, _, _, err := parseServiceInstanceName("") //nolint:dogsled
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// parseServiceInstanceName ↔ serviceInstanceName round-trip
// ---------------------------------------------------------------------------

func TestParseServiceInstanceName_RoundTrip(t *testing.T) {
	tests := []ServiceInstance{
		{Instance: "Simple", Service: "_http._tcp", Domain: "local"},
		{Instance: "Has.Dot", Service: "_http._tcp", Domain: "local"},
		{Instance: `Has\Backslash`, Service: "_ipp._tcp", Domain: "local"},
		{Instance: "Multicast DNS", Service: "_http._tcp", Domain: "dns-sd.org"},
		{Instance: "Stuart's Printer", Service: "_http._tcp", Domain: "dns-sd.org"},
	}
	for _, si := range tests {
		name := si.serviceInstanceName()
		inst, svc, dom, err := parseServiceInstanceName(name)
		require.NoError(t, err, "name=%q", name)
		assert.Equal(t, si.Instance, inst, "name=%q", name)
		assert.Equal(t, si.Service, svc, "name=%q", name)
		assert.Equal(t, si.Domain, dom, "name=%q", name)
	}
}

// ---------------------------------------------------------------------------
// validateServiceName — valid cases
// ---------------------------------------------------------------------------

func TestValidateServiceName_Valid(t *testing.T) {
	valid := []string{
		"_http._tcp",
		"_ipp._tcp",
		"_ssh._tcp",
		"_http._udp",
		"_custom._tcp",
		"_a._tcp",               // min: 1 char
		"_abcdefghijklmno._tcp", // max: 15 chars
		"_has-hyphen._tcp",
	}
	for _, s := range valid {
		assert.NoError(t, validateServiceName(s), "should be valid: %q", s)
	}
}

// ---------------------------------------------------------------------------
// validateServiceName — invalid cases (from test_vectors.md §9)
// ---------------------------------------------------------------------------

func TestValidateServiceName_Invalid(t *testing.T) {
	tests := []struct {
		input  string
		reason string
	}{
		{"_abcdefghijklmnop._tcp", "16 chars: exceeds 15-char limit"},
		{"http._tcp", "missing leading underscore on service"},
		{"_http.tcp", "missing leading underscore on proto"},
		{"_http._sctp", "proto must be _tcp or _udp"},
		{"_._tcp", "name portion empty (just underscore)"},
		{"_has space._tcp", "spaces not allowed in service name"},
		{"_-start._tcp", "must begin with letter or digit"},
		{"_end-._tcp", "must end with letter or digit"},
		{"_123._tcp", "must contain at least one letter"},
		{"_a--b._tcp", "consecutive hyphens"},
		{"", "empty string"},
		{"_http", "missing proto part"},
	}
	for _, tc := range tests {
		assert.Error(t, validateServiceName(tc.input), "should be invalid: %q (%s)", tc.input, tc.reason)
	}
}

// ---------------------------------------------------------------------------
// validateInstanceName
// ---------------------------------------------------------------------------

func TestValidateInstanceName_Valid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"simple", "My Printer"},
		{"with dots", "a.b.c"},
		{"with space", " hello "},
		{"63 bytes", strings.Repeat("a", 63)},
		{"unicode", "café"},
		{"punctuation", "Stuart's Printer"},
	}
	for _, tc := range tests {
		assert.NoError(t, validateInstanceName(tc.input), "should be valid: %s", tc.name)
	}
}

func TestValidateInstanceName_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"empty", "", errInstanceNameEmpty},
		{"too long", strings.Repeat("a", 64), errInstanceNameTooLong},
		{"null byte", "has\x00null", errInstanceNameHasControl},
		{"control 0x01", "has\x01ctrl", errInstanceNameHasControl},
		{"control 0x1F", "has\x1fctrl", errInstanceNameHasControl},
		{"DEL 0x7F", "has\x7fctrl", errInstanceNameHasControl},
	}
	for _, tc := range tests {
		err := validateInstanceName(tc.input)
		assert.ErrorIs(t, err, tc.expected, "case: %s", tc.name)
	}
}

func TestValidateInstanceName_SpaceIsValid(t *testing.T) {
	// 0x20 (space) is valid — it's above the control char range
	assert.NoError(t, validateInstanceName(" "))
}

// ---------------------------------------------------------------------------
// serviceTypeEnumerationName constant
// ---------------------------------------------------------------------------

func TestServiceTypeEnumerationName(t *testing.T) {
	assert.Equal(t, "_services._dns-sd._udp", serviceTypeEnumerationName)
}

// ---------------------------------------------------------------------------
// splitEscapedDots
// ---------------------------------------------------------------------------

func TestSplitEscapedDots(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"a.b.c", []string{"a", "b", "c"}},
		{`a\.b.c`, []string{`a\.b`, "c"}},
		{`a\\b.c`, []string{`a\\b`, "c"}},
		{`a\.b\.c`, []string{`a\.b\.c`}},
		{"single", []string{"single"}},
	}
	for _, tc := range tests {
		result := splitEscapedDots(tc.input)
		assert.Equal(t, tc.expected, result, "input=%q", tc.input)
	}
}
