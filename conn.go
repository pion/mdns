package mdns

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Conn represents a mDNS Server
type Conn struct {
	mu sync.RWMutex

	socket  *ipv4.PacketConn
	dstAddr *net.UDPAddr

	queryInterval time.Duration
	localNames    []string
	queries       map[string]chan queryResult
}

type queryResult struct {
	answer dnsmessage.ResourceHeader
	addr   net.Addr
}

const (
	inboundBufferSize    = 512
	defaultQueryInterval = time.Second
	destinationAddress   = "224.0.0.251:5353"
)

// Server establishes a mDNS connection over an existing conn
func Server(conn *ipv4.PacketConn, config *Config) (*Conn, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	joinErrCount := 0
	for i := range ifaces {
		if err = conn.JoinGroup(&ifaces[i], &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}); err != nil {
			joinErrCount++
		}
	}
	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	dstAddr, err := net.ResolveUDPAddr("udp", destinationAddress)
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

func (c *Conn) sendQuestion(name string) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		log.Fatal(err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{
			{
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
			{
				Type:  dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
		},
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := c.socket.WriteTo(rawQuery, nil, c.dstAddr); err != nil {
		log.Fatal(err)
	}
}

func ipToBytes(ip net.IP) (out [4]byte) {
	rawIP := ip.To4()
	if rawIP == nil {
		return
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(rawIP)
	copy(out[:], ipInt.Bytes())
	return
}

func (c *Conn) sendAnswer(name string) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		log.Fatal(err)
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					Name:  packedName,
				},
				Body: &dnsmessage.AResource{
					A: ipToBytes(net.ParseIP("192.168.0.1")), // TODO actual IP
				},
			},
		},
	}

	rawAnswer, err := msg.Pack()
	if err != nil {
		log.Fatal(err)
	}

	if _, err := c.socket.WriteTo(rawAnswer, nil, c.dstAddr); err != nil {
		log.Fatal(err)
	}
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, name string) (dnsmessage.ResourceHeader, net.Addr) {
	queryChan := make(chan queryResult, 1)
	c.mu.Lock()
	c.queries[name] = queryChan
	ticker := time.NewTicker(c.queryInterval)
	c.mu.Unlock()

	c.sendQuestion(name)
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(name)
		case res, ok := <-queryChan:
			if !ok {
				return dnsmessage.ResourceHeader{}, nil
			}
			return res.answer, res.addr
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, nil
		}
	}
}

func (c *Conn) start() {
	b := make([]byte, inboundBufferSize)
	p := dnsmessage.Parser{}

	for {
		n, _, src, err := c.socket.ReadFrom(b)
		if err != nil {
			log.Fatal("Read failed:", err)
			// TODO cleanup
		}

		func() {
			c.mu.RLock()
			defer c.mu.RUnlock()

			if _, err := p.Start(b[:n]); err != nil {
				fmt.Println(err)
			}

			for {
				q, err := p.Question()
				if err == dnsmessage.ErrSectionDone {
					break
				} else if err != nil {
					fmt.Println(err)
					return
				}

				for _, localName := range c.localNames {
					if localName == q.Name.String() {
						c.sendAnswer(q.Name.String())
					}
				}
			}

			for {
				a, err := p.AnswerHeader()
				if err == dnsmessage.ErrSectionDone {
					break
				}
				if err != nil {
					fmt.Println(err)
					return
				}

				if a.Type != dnsmessage.TypeA {
					continue
				}
				if resChan, ok := c.queries[a.Name.String()]; ok {
					resChan <- queryResult{a, src}
					delete(c.queries, a.Name.String())
				}

			}
		}()
	}
}
