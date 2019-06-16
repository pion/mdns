package mdns

import (
	"context"
	"encoding/hex"
	"log"
	"net"
	"time"
)

// Conn represents a mDNS Server
type Conn struct {
	queryInterval time.Duration
}

const (
	inboundBufferSize    = 512
	defaultQueryInterval = time.Second
)

func (c *Conn) start(conn net.PacketConn) {
	b := make([]byte, inboundBufferSize)
	for {
		n, src, err := conn.ReadFrom(b)
		if err != nil {
			log.Fatal("Read failed:", err)
		}

		log.Println(n, "bytes read from", src)
		log.Println(hex.Dump(b[:n]))
	}
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, name string) (Answer, *net.UDPAddr) {
	return Answer{}, nil
}

// Server establishes a mDNS connection over an existing conn
func Server(conn net.PacketConn, config *Config) (*Conn, error) {
	c := &Conn{
		queryInterval: defaultQueryInterval,
	}
	if config != nil {
		if config.QueryInterval != 0 {
			c.queryInterval = config.QueryInterval
		}
	}

	c.start(conn)
	return nil, nil
}
