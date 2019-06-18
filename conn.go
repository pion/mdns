package mdns

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Conn represents a mDNS Server
type Conn struct {
	mu sync.RWMutex

	socket  net.PacketConn
	dstAddr *net.UDPAddr

	queryInterval time.Duration
	localNames    []string
	queries       map[string]chan queryResult
}

type queryResult struct {
	answer Answer
	addr   net.Addr
}

const (
	inboundBufferSize    = 512
	defaultQueryInterval = time.Second
)

// Server establishes a mDNS connection over an existing conn
func Server(conn net.PacketConn, config *Config) (*Conn, error) {
	dstAddr, err := net.ResolveUDPAddr("udp", DefaultAddress)
	if err != nil {
		return nil, err

	}

	c := &Conn{
		queryInterval: defaultQueryInterval,
		queries:       map[string]chan queryResult{},
		socket:        conn,
		dstAddr:       dstAddr,
	}
	if config != nil {
		if config.QueryInterval != 0 {
			c.queryInterval = config.QueryInterval
		}
		c.localNames = append([]string(nil), config.LocalNames...)
	}

	go c.start()
	return c, nil
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, name string) (Answer, net.Addr) {
	queryChan := make(chan queryResult, 1)
	c.mu.Lock()
	c.queries[name] = queryChan
	ticker := time.NewTicker(c.queryInterval)
	c.mu.Unlock()

	sendQuery := func() {
		query := packet{
			questions: []*Question{
				{Name: name, Type: 0x01, Class: 0x01},
			},
		}
		rawQuery, err := query.Marshal()
		if err != nil {
			log.Fatal(err)
		}

		if _, err = c.socket.WriteTo(rawQuery, c.dstAddr); err != nil {
			log.Fatal(err)
		}
	}
	sendQuery()

	for {
		select {
		case <-ticker.C:
			sendQuery()
		case res, ok := <-queryChan:
			if !ok {
				return Answer{}, nil
			}
			return res.answer, res.addr
		case <-ctx.Done():
			return Answer{}, nil
		}
	}
}

func (c *Conn) start() {
	b := make([]byte, inboundBufferSize)
	pkt := packet{}

	for {
		n, src, err := c.socket.ReadFrom(b)
		if err != nil {
			log.Fatal("Read failed:", err)
			// TODO cleanup
		}

		func() {
			c.mu.RLock()
			defer c.mu.RUnlock()

			if err := pkt.Unmarshal(b[:n]); err != nil {
				fmt.Println(err)
				// Traffic can be anything, info at most
				return
			}

			for _, a := range pkt.answers {
				if resChan, ok := c.queries[a.Name]; ok {
					resChan <- queryResult{*a, src}
					delete(c.queries, a.Name)
				}
			}
		}()
	}
}
