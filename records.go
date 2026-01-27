// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// browseTTL is the recommended TTL for non-host-scoped records (browsing PTR,
// TXT) per RFC 6762 §10: 75 minutes = 4500 seconds.
const browseTTL uint32 = 4500

// maxTXTStringLen is the maximum length of a single constituent string within
// a DNS TXT record (RFC 1035 §3.3.14: 1-byte length prefix → max 255 bytes).
const maxTXTStringLen = 255

var (
	errTXTStringTooLong = errors.New("mDNS: TXT record string exceeds 255 bytes")
	errTXTKeyEmpty      = errors.New("mDNS: TXT record key must not be empty")
	errNotPTRResource   = errors.New("mDNS: resource body is not PTR")
	errNotSRVResource   = errors.New("mDNS: resource body is not SRV")
	errNotTXTResource   = errors.New("mDNS: resource body is not TXT")
)

// txtKeyValue represents a single key=value pair in a DNS-SD TXT record
// (RFC 6763 §6). Key is case-insensitive, printable US-ASCII (0x20-0x7E)
// excluding '=' (0x3D). Value is opaque bytes (often UTF-8).
//
// A nil Value indicates a boolean attribute — the key is simply present
// with no value. An empty (non-nil, zero-length) Value represents a key
// with an explicitly empty value (e.g. "PlugIns=").
type txtKeyValue struct {
	Key   string
	Value []byte // nil = boolean attribute (present, no value)
}

// encodeTXTRecordStrings converts key/value pairs into the wire-format
// strings for a DNS TXT resource record. Each entry becomes "key=value"
// or just "key" (boolean attribute). Returns an error if any single
// encoded string exceeds 255 bytes (RFC 1035 §3.3.14) or a key is empty.
//
// An empty input slice returns a single empty string, which represents
// the minimum valid TXT record (RFC 6763 §6.1).
func encodeTXTRecordStrings(pairs []txtKeyValue) ([]string, error) {
	if len(pairs) == 0 {
		return []string{""}, nil
	}

	out := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		if kv.Key == "" {
			return nil, errTXTKeyEmpty
		}

		var s string
		if kv.Value == nil {
			// Boolean attribute: key only, no '='
			s = kv.Key
		} else {
			// key=value (value may be empty)
			s = kv.Key + "=" + string(kv.Value)
		}

		if len(s) > maxTXTStringLen {
			return nil, errTXTStringTooLong
		}
		out = append(out, s)
	}

	return out, nil
}

// decodeTXTRecordStrings parses wire-format TXT record strings back into
// key/value pairs. Duplicate keys are deduplicated: only the first
// occurrence is kept (RFC 6763 §6.4). Strings where the key is empty
// (i.e. starting with '=') are silently ignored (RFC 6763 §6.4).
// Empty strings are skipped.
func decodeTXTRecordStrings(ss []string) []txtKeyValue {
	var out []txtKeyValue
	seen := make(map[string]struct{})

	for _, s := range ss {
		if s == "" {
			continue
		}

		var kv txtKeyValue
		if idx := strings.IndexByte(s, '='); idx >= 0 {
			kv.Key = s[:idx]
			kv.Value = []byte(s[idx+1:])
		} else {
			// Boolean attribute (no '=')
			kv.Key = s
			kv.Value = nil
		}

		// Empty key → silently ignore (RFC 6763 §6.4)
		if kv.Key == "" {
			continue
		}

		// Deduplicate: case-insensitive, keep first (RFC 6763 §6.4)
		lower := strings.ToLower(kv.Key)
		if _, exists := seen[lower]; exists {
			continue
		}
		seen[lower] = struct{}{}

		out = append(out, kv)
	}

	return out
}

// buildPTRResource creates a PTR resource record.
//
// Name is the query name (e.g. "_http._tcp.local.").
// Target is what the PTR points to (e.g. "My Web._http._tcp.local.").
// TTL is typically browseTTL (4500) for browsing PTRs (RFC 6762 §10).
func buildPTRResource(name, target string, ttl uint32) (dnsmessage.Resource, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	targetName, err := dnsmessage.NewName(target)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.PTRResource{PTR: targetName},
	}, nil
}

// buildSRVResource creates an SRV resource record.
//
// Name is the service instance FQDN (e.g. "My Web._http._tcp.local.").
// Target is the hostname (e.g. "myhost.local.").
// TTL is typically responseTTL (120) for host-scoped records (RFC 6762 §10).
func buildSRVResource(name, target string, port, priority, weight uint16, ttl uint32) (dnsmessage.Resource, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	targetName, err := dnsmessage.NewName(target)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypeSRV,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.SRVResource{
			Priority: priority,
			Weight:   weight,
			Port:     port,
			Target:   targetName,
		},
	}, nil
}

// buildTXTResource creates a TXT resource record.
//
// Name is the service instance FQDN.
// The txts slice contains pre-encoded TXT strings (each ≤ 255 bytes).
// TTL is typically browseTTL (4500) for TXT records (RFC 6762 §10).
func buildTXTResource(name string, txts []string, ttl uint32) (dnsmessage.Resource, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.TXTResource{TXT: txts},
	}, nil
}

// buildAResource creates an A resource record for an IPv4 address.
//
// TTL is typically responseTTL (120) for host address records (RFC 6762 §10).
func buildAResource(name string, addr netip.Addr, ttl uint32) (dnsmessage.Resource, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	ipBuf, err := ipv4ToBytes(addr)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.AResource{A: ipBuf},
	}, nil
}

// buildAAAAResource creates an AAAA resource record for an IPv6 address.
//
// TTL is typically responseTTL (120) for host address records (RFC 6762 §10).
func buildAAAAResource(name string, addr netip.Addr, ttl uint32) (dnsmessage.Resource, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	ipBuf, err := ipv6ToBytes(addr)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
			TTL:   ttl,
		},
		Body: &dnsmessage.AAAAResource{AAAA: ipBuf},
	}, nil
}

// parsePTRTarget extracts the target name string from a PTR resource body.
func parsePTRTarget(body dnsmessage.ResourceBody) (string, error) {
	ptr, ok := body.(*dnsmessage.PTRResource)
	if !ok {
		return "", errNotPTRResource
	}

	return ptr.PTR.String(), nil
}

// parseSRVData extracts the target hostname, port, priority, and weight
// from an SRV resource body.
func parseSRVData(body dnsmessage.ResourceBody) (target string, port, priority, weight uint16, err error) {
	srv, ok := body.(*dnsmessage.SRVResource)
	if !ok {
		return "", 0, 0, 0, errNotSRVResource
	}

	return srv.Target.String(), srv.Port, srv.Priority, srv.Weight, nil
}

// parseTXTData extracts the string slice from a TXT resource body.
func parseTXTData(body dnsmessage.ResourceBody) ([]string, error) {
	txt, ok := body.(*dnsmessage.TXTResource)
	if !ok {
		return nil, errNotTXTResource
	}

	return txt.TXT, nil
}
