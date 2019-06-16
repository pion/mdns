package mdns

import (
	"testing"
)

func TestFlagsParse(t *testing.T) {
	queryFlags := flags(0x0000)
	truncatedFlags := flags(0x400)
	responseFlags := flags(0x8400)

	if queryFlags.isQueryResponse() {
		t.Fatalf("Failed to parse % 02x as query", uint16(queryFlags))
	} else if queryFlags.isAuthoritativeOrTruncated() {
		t.Fatalf("Flag incorrectly declared as truncated % 02x ", uint16(queryFlags))
	}

	if !responseFlags.isQueryResponse() {
		t.Fatalf("Failed to parse % 02x as response", uint16(responseFlags))
	} else if !responseFlags.isAuthoritativeOrTruncated() {
		t.Fatalf("Flag incorrectly declared as non-authoritative % 02x ", uint16(responseFlags))
	}

	if !truncatedFlags.isAuthoritativeOrTruncated() {
		t.Fatalf("Flag incorrectly declared as non-truncated % 02x ", uint16(truncatedFlags))
	}
}

func TestFlagsSet(t *testing.T) {
	for i := 0; i <= 5; i++ {
		f := flags(0x0000)
		f.setIsQueryResponse(false)
		if f.isQueryResponse() {
			t.Fatalf("IsQuery unset failed % 02x", f)
		}
	}

	for i := 0; i <= 5; i++ {
		f := flags(0x0000)
		f.setIsQueryResponse(true)
		if !f.isQueryResponse() {
			t.Fatalf("IsQuery set failed % 02x", f)
		}
	}

	for i := 0; i <= 5; i++ {
		f := flags(0x0000)
		f.setIsAuthoritativeOrTruncated(true)
		if !f.isAuthoritativeOrTruncated() {
			t.Fatalf("IsAuthoritativeOrTruncated set failed % 02x", f)
		}
	}

	for i := 0; i <= 5; i++ {
		f := flags(0x0000)
		f.setIsAuthoritativeOrTruncated(false)
		if f.isAuthoritativeOrTruncated() {
			t.Fatalf("IsAuthoritativeOrTruncated unset failed % 02x", f)
		}
	}

}
