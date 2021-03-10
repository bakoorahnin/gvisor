// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package icmp_send_recv_dgram_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	ipv4Loopback = tcpip.Address("\x7f\x00\x00\x01")

	// Even though ICMP allows larger datagrams we don't test it here as they
	// need to be fragmented and written out as individual frames.
	maxPayloadSize = 1 << 10
)

func init() {
	testbench.Initialize(flag.CommandLine)
	testbench.RPCTimeout = 500 * time.Millisecond
}

type testResult uint8

type testCase struct {
	bindTo net.IP
	sendTo net.IP
	// sendToBroadcast defines if the socket should set the SO_BROADCAST socket
	// option.
	sendToBroadcast bool
	// bindToDevice defines if the ICMP socket should set the
	// SO_BINDTODEVICE socket option equal to the DUT's test interface.
	bindToDevice bool
	// expectData defines if the test runner should receive a packet.
	expectData bool
}

func TestICMPSocketBind(t *testing.T) {
	dut := testbench.NewDUT(t)

	tests := map[string]struct {
		bindTo        net.IP
		expectFailure bool
	}{
		"IPv4Zero": {
			bindTo:        net.IPv4zero,
			expectFailure: false,
		},
		"IPv4Loopback": {
			bindTo:        net.IPv4(127, 0, 0, 1),
			expectFailure: false,
		},
		"IPv4Unicast": {
			bindTo:        dut.Net.RemoteIPv4,
			expectFailure: false,
		},
		"IPv4UnknownUnicast": {
			bindTo:        dut.Net.LocalIPv4,
			expectFailure: true,
		},
		"IPv4MulticastAllSys": {
			bindTo:        net.IPv4allsys,
			expectFailure: true,
		},
		// TODO(gvisor.dev/issue/5711): Uncomment the test cases below once ICMP
		// sockets are no longer allowed to bind to broadcast addresses.
		//
		// "IPv4Broadcast": {
		//		bindTo:        net.IPv4bcast,
		// 		expectFailure: true,
		// },
		// "IPv4SubnetBroadcast": {
		// 		bindTo:        subnetBcast,
		// 		expectFailure: true,
		// },
		"IPv6Zero": {
			bindTo:        net.IPv6zero,
			expectFailure: false,
		},
		"IPv6Unicast": {
			bindTo:        dut.Net.RemoteIPv6,
			expectFailure: false,
		},
		"IPv6UnknownUnicast": {
			bindTo:        dut.Net.LocalIPv6,
			expectFailure: true,
		},
		"IPv6MulticastInterfaceLocalAllNodes": {
			bindTo:        net.IPv6interfacelocalallnodes,
			expectFailure: true,
		},
		"IPv6MulticastLinkLocalAllNodes": {
			bindTo:        net.IPv6linklocalallnodes,
			expectFailure: true,
		},
		"IPv6MulticastLinkLocalAllRouters": {
			bindTo:        net.IPv6linklocalallrouters,
			expectFailure: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var socketFD int32
			var sockaddr unix.Sockaddr

			if test.bindTo.To4() != nil {
				socketFD = dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
				bindTo := unix.SockaddrInet4{}
				copy(bindTo.Addr[:], test.bindTo.To4())
				sockaddr = &bindTo
			} else {
				socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
				bindTo := unix.SockaddrInet6{
					ZoneId: dut.Net.RemoteDevID,
				}
				copy(bindTo.Addr[:], test.bindTo.To16())
				sockaddr = &bindTo
			}

			ctx := context.Background()
			ret, err := dut.BindWithErrno(ctx, t, socketFD, sockaddr)

			if !test.expectFailure && ret != 0 {
				t.Fatalf("unexpected dut.BindWithErrno error: %v", err)
			}
			if test.expectFailure && ret == 0 {
				t.Fatalf("expected dut.BindWithErrno error")
			}
		})
	}
}

func TestICMPv4SocketSend(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcast := func() net.IP {
		subnet := (&tcpip.AddressWithPrefix{
			Address:   tcpip.Address(dut.Net.RemoteIPv4.To4()),
			PrefixLen: dut.Net.IPv4PrefixLength,
		}).Subnet()
		return net.IP(subnet.Broadcast())
	}()

	var tests []testCase

	for _, bindTo := range []net.IP{
		nil, // Do not bind.
		net.IPv4zero,
		dut.Net.RemoteIPv4,
	} {
		for _, sendTo := range []net.IP{
			// TODO(gvisor.dev/issue/5681): Uncomment the below addresses when
			// ICMP sockets allow sending to multicast and broadcast addresses.
			//
			// net.IPv4bcast,
			// net.IPv4allsys,
			// subnetBcast,
			dut.Net.LocalIPv4,
		} {
			for _, bindToDevice := range []bool{false, true} {
				expectData := true
				switch {
				case bindTo.Equal(dut.Net.RemoteIPv4):
					// If we're explicitly bound to an interface's unicast address,
					// packets are always sent on that interface.
				case bindToDevice:
					// If we're explicitly bound to an interface, packets are always
					// sent on that interface.
				case !sendTo.Equal(net.IPv4bcast) && !sendTo.IsMulticast():
					// If we're not sending to limited broadcast or multicast, the route table
					// will be consulted and packets will be sent on the correct interface.
				default:
					expectData = false
				}

				tests = append(tests, testCase{
					bindTo:          bindTo,
					sendTo:          sendTo,
					sendToBroadcast: sendTo.Equal(net.IPv4bcast) || sendTo.Equal(subnetBcast),
					bindToDevice:    bindToDevice,
					expectData:      expectData,
				})
			}
		}
	}

	for _, test := range tests {
		boundTestCaseName := "unbound"
		if test.bindTo != nil {
			boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
		}
		t.Run(fmt.Sprintf("%s/sendTo=%s/bindToDevice=%t/expectData=%t", boundTestCaseName, test.sendTo, test.bindToDevice, test.expectData), func(t *testing.T) {
			var socketFD int32
			var ident uint16

			// Tell the DUT to create a socket in preparation to send a packet.
			if test.bindTo != nil {
				socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMP, test.bindTo)
			} else {
				// An unbound socket will auto-bind to INNADDR_ANY.
				socketFD = dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
			}

			defer dut.Close(t, socketFD)
			if test.bindToDevice {
				dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
			}

			layers := testbench.Layers{
				expectedEthLayer(t, dut, test, socketFD),
				&testbench.IPv4{
					DstAddr: testbench.Address(tcpip.Address(test.sendTo.To4())),
				},
			}

			// Create a socket on the test runner and wait for a packet to come.
			conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			defer conn.Close(t)

			for name, payload := range map[string][]byte{
				"empty":    nil,
				"small":    []byte("hello world"),
				"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
			} {
				t.Run(name, func(t *testing.T) {
					// Tell the DUT to send a packet out the ICMP socket.
					icmpLayer := &testbench.ICMPv4{
						Type:    testbench.ICMPv4Type(header.ICMPv4Echo),
						Payload: payload,
					}
					bytes, err := icmpLayer.ToBytes()
					if err != nil {
						t.Fatalf("icmpLayer.ToBytes() = %s", err)
					}

					destSockaddr := unix.SockaddrInet4{}
					copy(destSockaddr.Addr[:], test.sendTo.To4())

					if got, want := dut.SendTo(t, socketFD, bytes, 0, &destSockaddr), len(bytes); int(got) != want {
						t.Fatalf("got dut.SendTo = %d, want %d", got, want)
					}

					// Verify the test runner received an ICMP packet with the
					// correctly set "ident" header.
					if ident != 0 {
						icmpLayer.Ident = &ident
					}
					_, err = conn.ExpectFrame(t, append(layers, icmpLayer), time.Second)
					if test.expectData && err != nil {
						t.Fatal(err)
					}
					if !test.expectData && err == nil {
						t.Fatal("received unexpected packet, socket is not bound to device")
					}
				})
			}
		})
	}
}

func TestICMPv6SocketSend(t *testing.T) {
	dut := testbench.NewDUT(t)
	var tests []testCase

	for _, bindTo := range []net.IP{
		nil, // Do not bind.
		net.IPv6zero,
		dut.Net.RemoteIPv6,
	} {
		for _, bindToDevice := range []bool{false, true} {
			tests = append(tests, testCase{
				bindTo:          bindTo,
				sendTo:          dut.Net.LocalIPv6,
				sendToBroadcast: false,
				bindToDevice:    bindToDevice,
				expectData:      true,
			})
		}
	}

	for _, test := range tests {
		boundTestCaseName := "unbound"
		if test.bindTo != nil {
			boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
		}
		t.Run(fmt.Sprintf("%s/sendTo=%s/bindToDevice=%t/expectData=%t", boundTestCaseName, test.sendTo, test.bindToDevice, test.expectData), func(t *testing.T) {
			var socketFD int32
			var ident uint16

			if test.bindTo != nil {
				socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6, test.bindTo)
			} else {
				// An unbound socket will auto-bind to INNADDR_ANY.
				socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
			}

			defer dut.Close(t, socketFD)
			if test.bindToDevice {
				dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
			}

			baseLayers := testbench.Layers{
				expectedEthLayer(t, dut, test, socketFD),
				&testbench.IPv6{
					DstAddr: testbench.Address(tcpip.Address(test.sendTo.To16())),
				},
			}

			conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			for name, payload := range map[string][]byte{
				"empty":    nil,
				"small":    []byte("hello world"),
				"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
			} {
				t.Run(name, func(t *testing.T) {
					icmpLayer := &testbench.ICMPv6{
						Type:    testbench.ICMPv6Type(header.ICMPv6EchoRequest),
						Payload: payload,
					}
					bytes, err := icmpLayer.ToBytes()
					if err != nil {
						t.Fatalf("icmpLayer.ToBytes() = %s", err)
					}

					destSockaddr := unix.SockaddrInet6{
						ZoneId: dut.Net.RemoteDevID,
					}
					copy(destSockaddr.Addr[:], test.sendTo.To16())

					if got, want := dut.SendTo(t, socketFD, bytes, 0, &destSockaddr), len(bytes); int(got) != want {
						t.Fatalf("got dut.SendTo = %d, want %d", got, want)
					}

					// Verify the test runner received an ICMP packet with the
					// correctly set "ident" header.
					if ident != 0 {
						icmpLayer.Ident = &ident
					}
					_, err = conn.ExpectFrame(t, append(baseLayers, icmpLayer), time.Second)
					if test.expectData && err != nil {
						t.Fatal(err)
					}
					if !test.expectData && err == nil {
						t.Fatal("received unexpected packet, socket is not bound to device")
					}
				})
			}
		})
	}
}

// TestICMPv4SocketReceive verifies ICMP sockets receive packets meant for them
// and do not receive packets that are not meant for them.
func TestICMPv4SocketReceive(t *testing.T) {
	dut := testbench.NewDUT(t)
	subnetBcast := func() net.IP {
		subnet := (&tcpip.AddressWithPrefix{
			Address:   tcpip.Address(dut.Net.RemoteIPv4.To4()),
			PrefixLen: dut.Net.IPv4PrefixLength,
		}).Subnet()
		return net.IP(subnet.Broadcast())
	}()

	var tests []testCase

	for _, bindTo := range []net.IP{
		nil, // Do not bind.
		net.IPv4zero,
		dut.Net.RemoteIPv4,
	} {
		for _, sendTo := range []net.IP{
			net.IPv4zero,
			net.IPv4bcast,
			net.IPv4allsys,
			subnetBcast,
			dut.Net.LocalIPv4,
			dut.Net.RemoteIPv4,
		} {
			if bindTo.Equal(net.IPv4zero) && (sendTo.Equal(net.IPv4bcast) || sendTo.Equal(subnetBcast) || sendTo.IsMulticast()) {
				// TODO(gvisor.dev/issue/5763): Remove this if statement once
				// gVisor restricts ICMP sockets to receive only from unicast
				// addresses.
				continue
			}
			for _, bindToDevice := range []bool{false, true} {
				tests = append(tests, testCase{
					bindTo:          bindTo,
					sendTo:          sendTo,
					sendToBroadcast: sendTo.Equal(net.IPv4bcast) || sendTo.Equal(subnetBcast),
					bindToDevice:    bindToDevice,
					expectData:      (bindTo.Equal(dut.Net.RemoteIPv4) || bindTo.Equal(net.IPv4zero)) && sendTo.Equal(dut.Net.RemoteIPv4),
				})
			}
		}
	}

	for _, test := range tests {
		boundTestCaseName := "unbound"
		if test.bindTo != nil {
			boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
		}
		t.Run(fmt.Sprintf("%s/sendTo=%s/bindToDevice=%t/expectData=%t", boundTestCaseName, test.sendTo, test.bindToDevice, test.expectData), func(t *testing.T) {
			var socketFD int32
			var ident uint16

			// Tell the DUT to create a socket and wait for a packet to come.
			if test.bindTo != nil {
				socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMP, test.bindTo)
			} else {
				// An unbound socket will auto-bind to INNADDR_ANY.
				socketFD = dut.Socket(t, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
			}

			defer dut.Close(t, socketFD)
			if test.bindToDevice {
				dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
			}

			baseLayers := testbench.Layers{
				expectedEthLayer(t, dut, test, socketFD),
				&testbench.IPv4{
					DstAddr: testbench.Address(tcpip.Address(test.sendTo.To4())),
				},
			}

			// Create a socket on the test runner in preparation to send a packet.
			conn := dut.Net.NewIPv4Conn(t, testbench.IPv4{}, testbench.IPv4{})
			defer conn.Close(t)

			for name, payload := range map[string][]byte{
				"empty":    nil,
				"small":    []byte("hello world"),
				"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
			} {
				t.Run(name, func(t *testing.T) {
					// Send an ICMPv4 packet from the test runner to the DUT.
					icmpLayer := &testbench.ICMPv4{
						Type:    testbench.ICMPv4Type(header.ICMPv4EchoReply),
						Payload: payload,
					}
					if ident != 0 {
						icmpLayer.Ident = &ident
					}
					frame := conn.CreateFrame(t, baseLayers, icmpLayer)
					conn.SendFrame(t, frame)

					// Verify the behavior of the ICMP socket on the DUT.
					if test.expectData {
						payload, err := icmpLayer.ToBytes()
						if err != nil {
							t.Fatalf("icmpLayer.ToBytes() = %s", err)
						}

						// Receive one extra byte to assert the length of the
						// packet received in the case where the packet contains
						// more data than expected.
						len := int32(len(payload)) + 1
						got, want := dut.Recv(t, socketFD, len, 0), payload
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
						}
					} else {
						// Expected receive error, set a short receive timeout.
						dut.SetSockOptTimeval(
							t,
							socketFD,
							unix.SOL_SOCKET,
							unix.SO_RCVTIMEO,
							&unix.Timeval{
								Sec:  1,
								Usec: 0,
							},
						)
						ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, socketFD, maxPayloadSize, 0)
						if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
							t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
						}
					}
				})
			}
		})
	}
}

// TestICMPv6SocketReceive verifies ICMP sockets receive packets meant for them
// and do not receive packets that are not meant for them.
func TestICMPv6SocketReceive(t *testing.T) {
	dut := testbench.NewDUT(t)

	var tests []testCase

	for _, bindTo := range []net.IP{
		nil, // Do not bind.
		net.IPv6zero,
		dut.Net.RemoteIPv6,
	} {
		for _, sendTo := range []net.IP{
			net.IPv6zero,
			net.IPv6interfacelocalallnodes,
			net.IPv6linklocalallnodes,
			net.IPv6linklocalallrouters,
			dut.Net.RemoteIPv6,
		} {
			if bindTo.Equal(net.IPv4zero) && (sendTo.Equal(net.IPv4bcast) || sendTo.IsMulticast()) {
				// TODO(gvisor.dev/issue/5763): Remove this if statement once
				// gVisor restricts ICMP sockets to receive only from unicast
				// addresses.
				continue
			}
			for _, bindToDevice := range []bool{false, true} {
				expectData := true
				switch {
				case bindTo.Equal(dut.Net.RemoteIPv6) && sendTo.Equal(dut.Net.RemoteIPv6):
				case bindTo.Equal(net.IPv6zero) && sendTo.Equal(dut.Net.RemoteIPv6):
				case bindTo.Equal(net.IPv6zero) && sendTo.Equal(net.IPv6linklocalallnodes):
				default:
					expectData = false
				}

				tests = append(tests, testCase{
					bindTo:          bindTo,
					sendTo:          sendTo,
					sendToBroadcast: false,
					bindToDevice:    bindToDevice,
					expectData:      expectData,
				})
			}
		}
	}

	for _, test := range tests {
		boundTestCaseName := "unbound"
		if test.bindTo != nil {
			boundTestCaseName = fmt.Sprintf("bindTo=%s", test.bindTo)
		}
		t.Run(fmt.Sprintf("%s/sendTo=%s/bindToDevice=%t/expectData=%t", boundTestCaseName, test.sendTo, test.bindToDevice, test.expectData), func(t *testing.T) {
			var socketFD int32
			var ident uint16

			// Tell the DUT to create a socket and wait for a packet to come.
			if test.bindTo != nil {
				socketFD, ident = dut.CreateBoundSocket(t, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6, test.bindTo)
			} else {
				// An unbound socket will auto-bind to INNADDR_ANY.
				socketFD = dut.Socket(t, unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_ICMPV6)
			}

			defer dut.Close(t, socketFD)
			if test.bindToDevice {
				dut.SetSockOpt(t, socketFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, []byte(dut.Net.RemoteDevName))
			}

			baseLayers := testbench.Layers{
				expectedEthLayer(t, dut, test, socketFD),
				&testbench.IPv6{
					DstAddr: testbench.Address(tcpip.Address(test.sendTo.To16())),
				},
			}

			// Create a socket on the test runner in preparation to send a packet.
			conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
			defer conn.Close(t)

			for name, payload := range map[string][]byte{
				"empty":    nil,
				"small":    []byte("hello world"),
				"random1k": testbench.GenerateRandomPayload(t, maxPayloadSize),
			} {
				t.Run(name, func(t *testing.T) {
					// Send an ICMPv4 packet from the test runner to the DUT.
					icmpLayer := &testbench.ICMPv6{
						Type:    testbench.ICMPv6Type(header.ICMPv6EchoReply),
						Payload: payload,
					}
					if ident != 0 {
						icmpLayer.Ident = &ident
					}
					frame := conn.CreateFrame(t, baseLayers, icmpLayer)
					conn.SendFrame(t, frame)

					// Verify the behavior of the ICMP socket on the DUT.
					if test.expectData {
						payload, err := icmpLayer.ToBytes()
						if err != nil {
							t.Fatalf("icmpLayer.ToBytes() = %s", err)
						}

						// Receive one extra byte to assert the length of the
						// packet received in the case where the packet contains
						// more data than expected.
						len := int32(len(payload)) + 1
						got, want := dut.Recv(t, socketFD, len, 0), payload
						if diff := cmp.Diff(want, got); diff != "" {
							t.Errorf("received payload does not match sent payload, diff (-want, +got):\n%s", diff)
						}
					} else {
						// Expected receive error, set a short receive timeout.
						dut.SetSockOptTimeval(
							t,
							socketFD,
							unix.SOL_SOCKET,
							unix.SO_RCVTIMEO,
							&unix.Timeval{
								Sec:  1,
								Usec: 0,
							},
						)
						ret, recvPayload, errno := dut.RecvWithErrno(context.Background(), t, socketFD, maxPayloadSize, 0)
						if errno != unix.EAGAIN || errno != unix.EWOULDBLOCK {
							t.Errorf("Recv got unexpected result, ret=%d, payload=%q, errno=%s", ret, recvPayload, errno)
						}
					}
				})
			}
		})
	}
}

func expectedEthLayer(t *testing.T, dut testbench.DUT, tc testCase, socketFD int32) testbench.Layer {
	t.Helper()
	var dst tcpip.LinkAddress
	if tc.sendToBroadcast {
		dut.SetSockOptInt(t, socketFD, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)

		// When sending to broadcast (subnet or limited), the expected ethernet
		// address is also broadcast.
		dst = header.EthernetBroadcastAddress
	} else if tc.sendTo.IsMulticast() {
		if sendToV4 := tc.sendTo.To4(); sendToV4 != nil {
			dst = header.EthernetAddressFromMulticastIPv4Address(tcpip.Address(sendToV4))
		} else {
			dst = header.EthernetAddressFromMulticastIPv6Address(tcpip.Address(tc.sendTo.To16()))
		}
	}
	return &testbench.Ether{
		DstAddr: &dst,
	}
}
