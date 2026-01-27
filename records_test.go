// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// ---------------------------------------------------------------------------
// TXT encoding — RFC 6763 §6.6 test vector
// ---------------------------------------------------------------------------

func TestEncodeTXTRecordStrings_RFC6763_Section6_6(t *testing.T) {
	// Test vector from RFC 6763 §6.6:
	//   | 0x09 | key=value | 0x08 | paper=A4 | 0x07 | passreq |
	pairs := []txtKeyValue{
		{Key: "key", Value: []byte("value")},
		{Key: "paper", Value: []byte("A4")},
		{Key: "passreq", Value: nil}, // boolean attribute
	}

	strs, err := encodeTXTRecordStrings(pairs)
	require.NoError(t, err)
	require.Len(t, strs, 3)

	assert.Equal(t, "key=value", strs[0])
	assert.Equal(t, "paper=A4", strs[1])
	assert.Equal(t, "passreq", strs[2])

	// Verify byte lengths match the spec's length-prefix bytes
	assert.Equal(t, 9, len(strs[0])) // 0x09
	assert.Equal(t, 8, len(strs[1])) // 0x08
	assert.Equal(t, 7, len(strs[2])) // 0x07
}

// ---------------------------------------------------------------------------
// TXT encoding — edge cases
// ---------------------------------------------------------------------------

func TestEncodeTXTRecordStrings_EmptyValue(t *testing.T) {
	// "PlugIns=" → key present, empty value (RFC 6763 §6.4)
	pairs := []txtKeyValue{
		{Key: "PlugIns", Value: []byte("")},
	}
	strs, err := encodeTXTRecordStrings(pairs)
	require.NoError(t, err)
	assert.Equal(t, []string{"PlugIns="}, strs)
}

func TestEncodeTXTRecordStrings_EmptyInput(t *testing.T) {
	// Empty pairs → single empty string (minimum valid TXT record, RFC 6763 §6.1)
	strs, err := encodeTXTRecordStrings(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{""}, strs)
}

func TestEncodeTXTRecordStrings_EmptyKey(t *testing.T) {
	pairs := []txtKeyValue{
		{Key: "", Value: []byte("bad")},
	}
	_, err := encodeTXTRecordStrings(pairs)
	assert.ErrorIs(t, err, errTXTKeyEmpty)
}

func TestEncodeTXTRecordStrings_MaxLength(t *testing.T) {
	// Exactly 255 bytes should succeed
	key := "k"
	val := strings.Repeat("x", 253) // "k=" + 253 = 255
	pairs := []txtKeyValue{{Key: key, Value: []byte(val)}}
	strs, err := encodeTXTRecordStrings(pairs)
	require.NoError(t, err)
	assert.Equal(t, 255, len(strs[0]))

	// 256 bytes should fail
	val256 := strings.Repeat("x", 254) // "k=" + 254 = 256
	pairs256 := []txtKeyValue{{Key: key, Value: []byte(val256)}}
	_, err = encodeTXTRecordStrings(pairs256)
	assert.ErrorIs(t, err, errTXTStringTooLong)
}

func TestEncodeTXTRecordStrings_BooleanMaxLength(t *testing.T) {
	// Boolean attribute: key only, 255 chars OK
	key255 := strings.Repeat("a", 255)
	pairs := []txtKeyValue{{Key: key255, Value: nil}}
	strs, err := encodeTXTRecordStrings(pairs)
	require.NoError(t, err)
	assert.Equal(t, 255, len(strs[0]))

	// 256 chars should fail
	key256 := strings.Repeat("a", 256)
	pairs256 := []txtKeyValue{{Key: key256, Value: nil}}
	_, err = encodeTXTRecordStrings(pairs256)
	assert.ErrorIs(t, err, errTXTStringTooLong)
}

// ---------------------------------------------------------------------------
// TXT decoding — RFC 6763 §6.6 test vector
// ---------------------------------------------------------------------------

func TestDecodeTXTRecordStrings_RFC6763_Section6_6(t *testing.T) {
	// Inverse of the encode test vector
	strs := []string{"key=value", "paper=A4", "passreq"}
	kvs := decodeTXTRecordStrings(strs)

	require.Len(t, kvs, 3)

	assert.Equal(t, "key", kvs[0].Key)
	assert.Equal(t, []byte("value"), kvs[0].Value)

	assert.Equal(t, "paper", kvs[1].Key)
	assert.Equal(t, []byte("A4"), kvs[1].Value)

	assert.Equal(t, "passreq", kvs[2].Key)
	assert.Nil(t, kvs[2].Value) // boolean
}

// ---------------------------------------------------------------------------
// TXT decoding — four categories from RFC 6763 §6.4
// ---------------------------------------------------------------------------

func TestDecodeTXTRecordStrings_FourCategories(t *testing.T) {
	strs := []string{
		"passreq",                  // boolean (present, no value)
		"PlugIns=",                 // present, empty value
		"PlugIns=JPEG,MPEG2,MPEG4", // duplicate — ignored
		"Color=4",                  // present, non-empty value
	}
	kvs := decodeTXTRecordStrings(strs)

	require.Len(t, kvs, 3) // PlugIns duplicate dropped

	// Boolean
	assert.Equal(t, "passreq", kvs[0].Key)
	assert.Nil(t, kvs[0].Value)

	// Empty value
	assert.Equal(t, "PlugIns", kvs[1].Key)
	assert.Equal(t, []byte(""), kvs[1].Value)

	// Non-empty value
	assert.Equal(t, "Color", kvs[2].Key)
	assert.Equal(t, []byte("4"), kvs[2].Value)
}

func TestDecodeTXTRecordStrings_ValueContainingEquals(t *testing.T) {
	// "equation=x=y" → key "equation", value "x=y" (split on first '=' only)
	kvs := decodeTXTRecordStrings([]string{"equation=x=y"})
	require.Len(t, kvs, 1)
	assert.Equal(t, "equation", kvs[0].Key)
	assert.Equal(t, []byte("x=y"), kvs[0].Value)
}

func TestDecodeTXTRecordStrings_EmptyKeyIgnored(t *testing.T) {
	// "=bad" → key is empty → silently ignored (RFC 6763 §6.4)
	kvs := decodeTXTRecordStrings([]string{"=bad"})
	assert.Empty(t, kvs)
}

func TestDecodeTXTRecordStrings_EmptyStringIgnored(t *testing.T) {
	kvs := decodeTXTRecordStrings([]string{"", "ok=val", ""})
	require.Len(t, kvs, 1)
	assert.Equal(t, "ok", kvs[0].Key)
}

func TestDecodeTXTRecordStrings_DuplicateKeys_CaseInsensitive(t *testing.T) {
	// RFC 6763 §6.4: case-insensitive dedup, keep first
	strs := []string{"papersize=A4", "PAPERSIZE=Letter", "Papersize=A3"}
	kvs := decodeTXTRecordStrings(strs)

	require.Len(t, kvs, 1)
	assert.Equal(t, "papersize", kvs[0].Key) // original case preserved
	assert.Equal(t, []byte("A4"), kvs[0].Value)
}

func TestDecodeTXTRecordStrings_SpacesInKey(t *testing.T) {
	// RFC 6763 §6.4: spaces in keys are significant
	kvs := decodeTXTRecordStrings([]string{" key =value"})
	require.Len(t, kvs, 1)
	assert.Equal(t, " key ", kvs[0].Key)
	assert.Equal(t, []byte("value"), kvs[0].Value)
}

// ---------------------------------------------------------------------------
// TXT round-trip: encode → decode
// ---------------------------------------------------------------------------

func TestTXTRoundTrip(t *testing.T) {
	original := []txtKeyValue{
		{Key: "txtvers", Value: []byte("1")},
		{Key: "path", Value: []byte("/")},
		{Key: "secure", Value: nil},
		{Key: "empty", Value: []byte("")},
	}

	strs, err := encodeTXTRecordStrings(original)
	require.NoError(t, err)
	decoded := decodeTXTRecordStrings(strs)

	require.Len(t, decoded, len(original))
	for i, kv := range original {
		assert.Equal(t, kv.Key, decoded[i].Key)
		if kv.Value == nil {
			assert.Nil(t, decoded[i].Value)
		} else {
			assert.Equal(t, kv.Value, decoded[i].Value)
		}
	}
}

// ---------------------------------------------------------------------------
// Record builders — PTR
// ---------------------------------------------------------------------------

func TestBuildPTRResource(t *testing.T) {
	res, err := buildPTRResource("_http._tcp.local.", "My Web._http._tcp.local.", browseTTL)
	require.NoError(t, err)

	assert.Equal(t, dnsmessage.TypePTR, res.Header.Type)
	assert.Equal(t, dnsmessage.ClassINET, res.Header.Class)
	assert.Equal(t, browseTTL, res.Header.TTL)

	target, err := parsePTRTarget(res.Body)
	require.NoError(t, err)
	assert.Equal(t, "My Web._http._tcp.local.", target)
}

func TestBuildPTRResource_InvalidName(t *testing.T) {
	// dnsmessage.NewName rejects names of 256+ bytes.
	longName := strings.Repeat("a", 255) + "."
	_, err := buildPTRResource(longName, "target.local.", 300)
	assert.Error(t, err)
}

func TestBuildPTRResource_CustomTTL(t *testing.T) {
	res, err := buildPTRResource("_ipp._tcp.local.", "printer._ipp._tcp.local.", 300)
	require.NoError(t, err)
	assert.Equal(t, uint32(300), res.Header.TTL)
}

// ---------------------------------------------------------------------------
// Record builders — SRV
// ---------------------------------------------------------------------------

func TestBuildSRVResource(t *testing.T) {
	// Test vector from RFC 6763 §13.3:
	// SRV priority=0, weight=0, port=80, host=dns-sd.org
	res, err := buildSRVResource(
		"Service Discovery._http._tcp.dns-sd.org.",
		"dns-sd.org.",
		80, 0, 0, responseTTL,
	)
	require.NoError(t, err)

	assert.Equal(t, dnsmessage.TypeSRV, res.Header.Type)
	assert.Equal(t, dnsmessage.ClassINET, res.Header.Class)
	assert.Equal(t, uint32(responseTTL), res.Header.TTL)

	target, port, priority, weight, err := parseSRVData(res.Body)
	require.NoError(t, err)
	assert.Equal(t, "dns-sd.org.", target)
	assert.Equal(t, uint16(80), port)
	assert.Equal(t, uint16(0), priority)
	assert.Equal(t, uint16(0), weight)
}

func TestBuildSRVResource_NonZeroPriorityWeight(t *testing.T) {
	res, err := buildSRVResource("svc._tcp.local.", "host.local.", 8080, 10, 20, 300)
	require.NoError(t, err)

	assert.Equal(t, uint32(300), res.Header.TTL)
	_, port, priority, weight, err := parseSRVData(res.Body)
	require.NoError(t, err)
	assert.Equal(t, uint16(8080), port)
	assert.Equal(t, uint16(10), priority)
	assert.Equal(t, uint16(20), weight)
}

// ---------------------------------------------------------------------------
// Record builders — TXT
// ---------------------------------------------------------------------------

func TestBuildTXTResource(t *testing.T) {
	// Test vector from RFC 6763 §13.3:
	// TXT "txtvers=1" "path=/"
	res, err := buildTXTResource(
		"Service Discovery._http._tcp.dns-sd.org.",
		[]string{"txtvers=1", "path=/"},
		browseTTL,
	)
	require.NoError(t, err)

	assert.Equal(t, dnsmessage.TypeTXT, res.Header.Type)
	assert.Equal(t, dnsmessage.ClassINET, res.Header.Class)
	assert.Equal(t, browseTTL, res.Header.TTL)

	txts, err := parseTXTData(res.Body)
	require.NoError(t, err)
	assert.Equal(t, []string{"txtvers=1", "path=/"}, txts)
}

func TestBuildTXTResource_Empty(t *testing.T) {
	// Minimum valid TXT record: single empty string
	res, err := buildTXTResource("svc._tcp.local.", []string{""}, 300)
	require.NoError(t, err)

	assert.Equal(t, uint32(300), res.Header.TTL)
	txts, err := parseTXTData(res.Body)
	require.NoError(t, err)
	assert.Equal(t, []string{""}, txts)
}

// ---------------------------------------------------------------------------
// Record builders — A
// ---------------------------------------------------------------------------

func TestBuildAResource(t *testing.T) {
	// Test vector from RFC 6763 §13.3: dns-sd.org = 64.142.82.154
	addr := netip.MustParseAddr("64.142.82.154")
	res, err := buildAResource("dns-sd.org.", addr, responseTTL)
	require.NoError(t, err)

	assert.Equal(t, dnsmessage.TypeA, res.Header.Type)
	assert.Equal(t, dnsmessage.ClassINET, res.Header.Class)
	assert.Equal(t, uint32(responseTTL), res.Header.TTL)

	body, ok := res.Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{64, 142, 82, 154}, body.A)
}

func TestBuildAResource_RejectsIPv6(t *testing.T) {
	addr := netip.MustParseAddr("::1")
	_, err := buildAResource("host.local.", addr, 300)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Record builders — AAAA
// ---------------------------------------------------------------------------

func TestBuildAAAAResource(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	res, err := buildAAAAResource("host.local.", addr, responseTTL)
	require.NoError(t, err)

	assert.Equal(t, dnsmessage.TypeAAAA, res.Header.Type)
	assert.Equal(t, dnsmessage.ClassINET, res.Header.Class)
	assert.Equal(t, uint32(responseTTL), res.Header.TTL)

	body, ok := res.Body.(*dnsmessage.AAAAResource)
	require.True(t, ok)
	expected := netip.MustParseAddr("fd00::1").As16()
	assert.Equal(t, expected, body.AAAA)
}

func TestBuildAAAAResource_RejectsIPv4(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.1")
	_, err := buildAAAAResource("host.local.", addr, 300)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Record round-trip: build → pack → unpack → parse
// ---------------------------------------------------------------------------

func TestPTRRoundTrip(t *testing.T) {
	res, err := buildPTRResource("_http._tcp.local.", "My Web._http._tcp.local.", 4500)
	require.NoError(t, err)

	msg := packSingleAnswer(t, res)
	parsed := unpackFirstAnswer(t, msg)

	assert.Equal(t, dnsmessage.TypePTR, parsed.Header.Type)
	target, err := parsePTRTarget(parsed.Body)
	require.NoError(t, err)
	assert.Equal(t, "My Web._http._tcp.local.", target)
}

func TestSRVRoundTrip(t *testing.T) {
	res, err := buildSRVResource("svc._http._tcp.local.", "myhost.local.", 8080, 0, 0, 120)
	require.NoError(t, err)

	msg := packSingleAnswer(t, res)
	parsed := unpackFirstAnswer(t, msg)

	assert.Equal(t, dnsmessage.TypeSRV, parsed.Header.Type)
	target, port, priority, weight, err := parseSRVData(parsed.Body)
	require.NoError(t, err)
	assert.Equal(t, "myhost.local.", target)
	assert.Equal(t, uint16(8080), port)
	assert.Equal(t, uint16(0), priority)
	assert.Equal(t, uint16(0), weight)
}

func TestTXTRoundTrip_DNS(t *testing.T) {
	res, err := buildTXTResource("svc._tcp.local.", []string{"txtvers=1", "path=/"}, 4500)
	require.NoError(t, err)

	msg := packSingleAnswer(t, res)
	parsed := unpackFirstAnswer(t, msg)

	assert.Equal(t, dnsmessage.TypeTXT, parsed.Header.Type)
	txts, err := parseTXTData(parsed.Body)
	require.NoError(t, err)
	assert.Equal(t, []string{"txtvers=1", "path=/"}, txts)
}

func TestARoundTrip(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.100")
	res, err := buildAResource("myhost.local.", addr, 120)
	require.NoError(t, err)

	msg := packSingleAnswer(t, res)
	parsed := unpackFirstAnswer(t, msg)

	assert.Equal(t, dnsmessage.TypeA, parsed.Header.Type)
	body, ok := parsed.Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{192, 168, 1, 100}, body.A)
}

func TestAAAARoundTrip(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	res, err := buildAAAAResource("myhost.local.", addr, 120)
	require.NoError(t, err)

	msg := packSingleAnswer(t, res)
	parsed := unpackFirstAnswer(t, msg)

	assert.Equal(t, dnsmessage.TypeAAAA, parsed.Header.Type)
	body, ok := parsed.Body.(*dnsmessage.AAAAResource)
	require.True(t, ok)
	expected := netip.MustParseAddr("fd00::1").As16()
	assert.Equal(t, expected, body.AAAA)
}

// ---------------------------------------------------------------------------
// Full TXT encode → build → pack → unpack → parse → decode round-trip
// ---------------------------------------------------------------------------

func TestTXTFullRoundTrip(t *testing.T) {
	// RFC 6763 §6.6 test vector
	pairs := []txtKeyValue{
		{Key: "key", Value: []byte("value")},
		{Key: "paper", Value: []byte("A4")},
		{Key: "passreq", Value: nil},
	}

	// Encode key/value → strings
	strs, err := encodeTXTRecordStrings(pairs)
	require.NoError(t, err)

	// Build TXT resource
	res, err := buildTXTResource("svc._tcp.local.", strs, browseTTL)
	require.NoError(t, err)

	// Pack → unpack
	msg := packSingleAnswer(t, res)
	parsed := unpackFirstAnswer(t, msg)

	// Parse TXT body → strings
	roundTripped, err := parseTXTData(parsed.Body)
	require.NoError(t, err)

	// Decode strings → key/value
	decoded := decodeTXTRecordStrings(roundTripped)
	require.Len(t, decoded, 3)

	assert.Equal(t, "key", decoded[0].Key)
	assert.Equal(t, []byte("value"), decoded[0].Value)

	assert.Equal(t, "paper", decoded[1].Key)
	assert.Equal(t, []byte("A4"), decoded[1].Value)

	assert.Equal(t, "passreq", decoded[2].Key)
	assert.Nil(t, decoded[2].Value)
}

// ---------------------------------------------------------------------------
// TTL constants — RFC 6762 §10
// ---------------------------------------------------------------------------

func TestTTLConstants(t *testing.T) {
	// Host-scoped records: 120 seconds (RFC 6762 §10)
	assert.Equal(t, uint32(120), uint32(responseTTL))

	// Browsing/other records: 4500 seconds = 75 minutes (RFC 6762 §10)
	assert.Equal(t, uint32(4500), browseTTL)
}

// ---------------------------------------------------------------------------
// Parse helpers — wrong body type
// ---------------------------------------------------------------------------

func TestParsePTRTarget_WrongType(t *testing.T) {
	_, err := parsePTRTarget(&dnsmessage.AResource{})
	assert.Error(t, err)
}

func TestParseSRVData_WrongType(t *testing.T) {
	_, _, _, _, err := parseSRVData(&dnsmessage.AResource{}) //nolint:dogsled
	assert.Error(t, err)
}

func TestParseTXTData_WrongType(t *testing.T) {
	_, err := parseTXTData(&dnsmessage.AResource{})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Multi-record message — simulating additional record generation (§12)
// ---------------------------------------------------------------------------

func TestMultiRecordMessage(t *testing.T) {
	// Simulate a PTR response with SRV + TXT + A additional records,
	// as recommended by RFC 6763 §12.1
	ptr, err := buildPTRResource("_http._tcp.local.", "My Web._http._tcp.local.", browseTTL)
	require.NoError(t, err)

	srv, err := buildSRVResource("My Web._http._tcp.local.", "myhost.local.", 8080, 0, 0, responseTTL)
	require.NoError(t, err)

	txt, err := buildTXTResource("My Web._http._tcp.local.", []string{"path=/"}, browseTTL)
	require.NoError(t, err)

	addr := netip.MustParseAddr("192.168.1.100")
	aRec, err := buildAResource("myhost.local.", addr, responseTTL)
	require.NoError(t, err)

	addrV6 := netip.MustParseAddr("fd00::1")
	aaaaRec, err := buildAAAAResource("myhost.local.", addrV6, responseTTL)
	require.NoError(t, err)

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers:     []dnsmessage.Resource{ptr},
		Additionals: []dnsmessage.Resource{srv, txt, aRec, aaaaRec},
	}

	raw, err := msg.Pack()
	require.NoError(t, err)

	var unpacked dnsmessage.Message
	err = unpacked.Unpack(raw)
	require.NoError(t, err)

	// Verify answer: PTR
	require.Len(t, unpacked.Answers, 1)
	assert.Equal(t, dnsmessage.TypePTR, unpacked.Answers[0].Header.Type)
	ptrTarget, err := parsePTRTarget(unpacked.Answers[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "My Web._http._tcp.local.", ptrTarget)

	// Verify additionals: SRV, TXT, A, AAAA
	require.Len(t, unpacked.Additionals, 4)
	assert.Equal(t, dnsmessage.TypeSRV, unpacked.Additionals[0].Header.Type)
	assert.Equal(t, dnsmessage.TypeTXT, unpacked.Additionals[1].Header.Type)
	assert.Equal(t, dnsmessage.TypeA, unpacked.Additionals[2].Header.Type)
	assert.Equal(t, dnsmessage.TypeAAAA, unpacked.Additionals[3].Header.Type)

	// Verify SRV data
	srvTarget, srvPort, _, _, err := parseSRVData(unpacked.Additionals[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "myhost.local.", srvTarget)
	assert.Equal(t, uint16(8080), srvPort)

	// Verify A data
	aBody, ok := unpacked.Additionals[2].Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{192, 168, 1, 100}, aBody.A)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func packSingleAnswer(t *testing.T, res dnsmessage.Resource) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{res},
	}
	raw, err := msg.Pack()
	require.NoError(t, err)

	return raw
}

func unpackFirstAnswer(t *testing.T, raw []byte) dnsmessage.Resource {
	t.Helper()
	var msg dnsmessage.Message
	err := msg.Unpack(raw)
	require.NoError(t, err)
	require.NotEmpty(t, msg.Answers)

	return msg.Answers[0]
}
