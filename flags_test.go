package mdns

import (
	"testing"
)

func TestFlagsisResponse(t *testing.T) {
	queryFlags := flags(0x0000)
	responseFlags := flags(0x8400)

	if !queryFlags.isQuery() {
		t.Fatalf("Failed to parse % 02x as query", uint16(queryFlags))
	}

	if responseFlags.isQuery() {
		t.Fatalf("Failed to parse % 02x as response", uint16(responseFlags))
	}
}
