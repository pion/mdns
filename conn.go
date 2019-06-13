package mdns

import (
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

// func (c *Conn) Query(name s) {
// }

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
