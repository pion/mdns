// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"net"

	"github.com/pion/logging"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ipControlMessage struct {
	IfIndex int
	Dst     net.IP
}

type ipPacketConn interface {
	ReadFrom(b []byte) (n int, cm *ipControlMessage, src net.Addr, err error)
	WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error)
	Close() error
}

type ipPacketConn4 struct {
	name string
	conn *ipv4.PacketConn
	log  logging.LeveledLogger
}

func (c ipPacketConn4) ReadFrom(b []byte) (n int, cm *ipControlMessage, src net.Addr, err error) {
	n, cm4, src, err := c.conn.ReadFrom(b)
	if err != nil || cm4 == nil {
		return n, nil, src, err
	}

	return n, &ipControlMessage{IfIndex: cm4.IfIndex, Dst: cm4.Dst}, src, err
}

func (c ipPacketConn4) WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error) {
	var cm4 *ipv4.ControlMessage
	if cm != nil {
		cm4 = &ipv4.ControlMessage{
			IfIndex: cm.IfIndex,
		}
	}
	if err := c.conn.SetMulticastInterface(via); err != nil {
		c.log.Warnf("[%s] failed to set multicast interface for %d: %v", c.name, via.Index, err)

		return 0, err
	}

	return c.conn.WriteTo(b, cm4, dst)
}

func (c ipPacketConn4) Close() error {
	return c.conn.Close()
}

type ipPacketConn6 struct {
	name string
	conn *ipv6.PacketConn
	log  logging.LeveledLogger
}

func (c ipPacketConn6) ReadFrom(b []byte) (n int, cm *ipControlMessage, src net.Addr, err error) {
	n, cm6, src, err := c.conn.ReadFrom(b)
	if err != nil || cm6 == nil {
		return n, nil, src, err
	}

	return n, &ipControlMessage{IfIndex: cm6.IfIndex, Dst: cm6.Dst}, src, err
}

func (c ipPacketConn6) WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error) {
	var cm6 *ipv6.ControlMessage
	if cm != nil {
		cm6 = &ipv6.ControlMessage{
			IfIndex: cm.IfIndex,
		}
	}
	if err := c.conn.SetMulticastInterface(via); err != nil {
		c.log.Warnf("[%s] failed to set multicast interface for %d: %v", c.name, via.Index, err)

		return 0, err
	}

	return c.conn.WriteTo(b, cm6, dst)
}

func (c ipPacketConn6) Close() error {
	return c.conn.Close()
}

// configurePacketConn4 sets up control messages on an IPv4 PacketConn and returns the wrapper.
// Returns nil if pc is nil.
func configurePacketConn4(pc *ipv4.PacketConn, name, connType string, log logging.LeveledLogger) ipPacketConn {
	if pc == nil {
		return nil
	}
	if err := pc.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		log.Warnf("[%s] failed to SetControlMessage(FlagInterface) on %s IPv4 PacketConn: %v", name, connType, err)
	}
	if err := pc.SetControlMessage(ipv4.FlagDst, true); err != nil {
		log.Warnf("[%s] failed to SetControlMessage(FlagDst) on %s IPv4 PacketConn: %v", name, connType, err)
	}

	return ipPacketConn4{name, pc, log}
}

// configurePacketConn6 sets up control messages on an IPv6 PacketConn and returns the wrapper.
// Returns nil if pc is nil.
func configurePacketConn6(pc *ipv6.PacketConn, name, connType string, log logging.LeveledLogger) ipPacketConn {
	if pc == nil {
		return nil
	}
	if err := pc.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		log.Warnf("[%s] failed to SetControlMessage(FlagInterface) on %s IPv6 PacketConn: %v", name, connType, err)
	}
	if err := pc.SetControlMessage(ipv6.FlagDst, true); err != nil {
		log.Warnf("[%s] failed to SetControlMessage(FlagDst) on %s IPv6 PacketConn: %v", name, connType, err)
	}

	return ipPacketConn6{name, pc, log}
}

// enableLoopback4 enables multicast loopback on an IPv4 PacketConn if non-nil.
func enableLoopback4(pc *ipv4.PacketConn, name, connType string, log logging.LeveledLogger) {
	if pc == nil {
		return
	}
	if err := pc.SetMulticastLoopback(true); err != nil {
		log.Warnf("[%s] failed to SetMulticastLoopback on %s IPv4 PacketConn: %v", name, connType, err)
	}
}

// enableLoopback6 enables multicast loopback on an IPv6 PacketConn if non-nil.
func enableLoopback6(pc *ipv6.PacketConn, name, connType string, log logging.LeveledLogger) {
	if pc == nil {
		return
	}
	if err := pc.SetMulticastLoopback(true); err != nil {
		log.Warnf("[%s] failed to SetMulticastLoopback on %s IPv6 PacketConn: %v", name, connType, err)
	}
}
