package engine

import (
	"context"
	"net"
	"net/netip"
	"os"
	"testing"

	"brof.dev/headwire/internal/config"
	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	gvheader "gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"tailscale.com/net/netns"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

// init disables netns for the whole test binary. Unprivileged netns binds
// underlay sockets to the default interface, so the loopback endpoints most
// tests use would never connect.
func init() {
	netns.SetEnabled(false)
}

// testStack is a gVisor TCP/IP stack behind a tun.Device, standing in for the
// host or provider stack on the far side of an injected device.
type testStack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	events chan tun.Event
}

// newTestStack holds cfg's interface addresses and routes both families to the
// device.
func newTestStack(t *testing.T, cfg *config.Config) *testStack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	ep := channel.New(1024, uint32(MTU(cfg)), "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Interface.Addresses {
		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          protocol(p.Addr()),
			AddressWithPrefix: tcpip.AddrFromSlice(p.Addr().AsSlice()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: gvheader.IPv4EmptySubnet, NIC: 1},
		{Destination: gvheader.IPv6EmptySubnet, NIC: 1},
	})
	events := make(chan tun.Event, 1)
	events <- tun.EventUp
	return &testStack{
		s:      s,
		ep:     ep,
		events: events,
	}
}

func protocol(ip netip.Addr) tcpip.NetworkProtocolNumber {
	if ip.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func fullAddr(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()),
		Port: a.Port(),
	}
}

func (s *testStack) File() *os.File           { return nil }
func (s *testStack) MTU() (int, error)        { return int(s.ep.MTU()), nil }
func (s *testStack) Name() (string, error)    { return "hwtest", nil }
func (s *testStack) Events() <-chan tun.Event { return s.events }
func (s *testStack) BatchSize() int           { return 1 }

// Read hands the engine one packet the stack sent.
func (s *testStack) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	pkt := s.ep.ReadContext(context.Background())
	if pkt == nil {
		return 0, os.ErrClosed
	}
	defer pkt.DecRef()
	view := pkt.ToView()
	defer view.Release()
	packets[0] = tun.ReadPacket{
		Offset: tun.ReadPacketSpacing,
		Size:   copy(slab[tun.ReadPacketSpacing:len(slab)-tun.ReadPacketSpacing], view.AsSlice()),
	}
	return 1, nil
}

// Write delivers the engine's packets to the stack.
func (s *testStack) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		proto := ipv4.ProtocolNumber
		if b[offset]>>4 == 6 {
			proto = ipv6.ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b[offset:])})
		s.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func (s *testStack) Close() error {
	s.s.Destroy()
	close(s.events)
	return nil
}

func (s *testStack) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, s.s, fullAddr(dst), protocol(dst.Addr()))
}

func (s *testStack) listenUDP(t *testing.T, local netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	laddr := fullAddr(local)
	c, err := gonet.DialUDP(s.s, &laddr, nil, protocol(local.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// testNode is an engine on a testStack.
type testNode struct {
	*Engine
	stack *testStack
}

// startNode leaves closing the engine to the caller.
func startNode(t *testing.T, cfg *config.Config, logf logger.Logf) (*testNode, error) {
	t.Helper()
	s := newTestStack(t, cfg)
	e, err := Start(cfg, logf, Options{Tun: s})
	return &testNode{
		Engine: e,
		stack:  s,
	}, err
}

// startEcho serves echo on testEchoPort at every interface address.
func startEcho(t *testing.T, cfg *config.Config) *testNode {
	t.Helper()
	n, err := startNode(t, cfg, tstest.WhileTestRunningLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	n.serve(t, testEchoPort, func(c net.Conn) { echo(context.Background(), c) })
	return n
}

// serve runs handle for each TCP connection to port at an interface address
// until the stack closes.
func (n *testNode) serve(t *testing.T, port uint16, handle func(net.Conn)) {
	t.Helper()
	for _, p := range n.state.Load().cfg.Interface.Addresses {
		l, err := gonet.ListenTCP(n.stack.s, fullAddr(netip.AddrPortFrom(p.Addr(), port)), protocol(p.Addr()))
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go handle(c)
			}
		}()
	}
}
