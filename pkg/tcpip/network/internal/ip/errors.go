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

package ip

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// ForwardingError represents an error that occured while trying to forward
// a packet.
type ForwardingError interface {
	isForwardingError()
	fmt.Stringer
}

// ErrTTLExceeded indicates that the received packet's TTL has been exceeded.
type ErrTTLExceeded struct{}

func (*ErrTTLExceeded) isForwardingError() {}

func (*ErrTTLExceeded) String() string { return "ttl exceeded" }

// ErrIPOptProblem indicates the received packet had a problem with an IP
// option.
type ErrIPOptProblem struct{}

func (*ErrIPOptProblem) isForwardingError() {}

func (*ErrIPOptProblem) String() string { return "ip option problem" }

// ErrLinkLocalSourceAddress indicates the received packet had a link-local
// source address.
type ErrLinkLocalSourceAddress struct{}

func (*ErrLinkLocalSourceAddress) isForwardingError() {}

func (*ErrLinkLocalSourceAddress) String() string { return "link local destination address" }

// ErrLinkLocalDestAddress indicates the received packet had a link-local
// destination address.
type ErrLinkLocalDestAddress struct{}

func (*ErrLinkLocalDestAddress) isForwardingError() {}

func (*ErrLinkLocalDestAddress) String() string { return "link local dest address" }

// ErrCantCreateRoute indicates the Netstack couldn't create a route for the
// received packet.
type ErrCantCreateRoute struct{}

func (*ErrCantCreateRoute) isForwardingError() {}

func (*ErrCantCreateRoute) String() string { return "cant create route" }

// ErrUnknown indicates the packet coould not be forwarded for an unknown
// reason captured by the contained error.
type ErrUnknown struct {
	Err tcpip.Error
}

func (*ErrUnknown) isForwardingError() {}

func (e *ErrUnknown) String() string { return fmt.Sprintf("unknown tcpip error: %s", e.Err) }

// ErrIPv6ExtensionHeaderProblem indicates a problem with one of the received
// packet's IPv6 extension headers.
type ErrIPv6ExtensionHeaderProblem struct {
	Err IPv6ExtensionHeaderProcessingError
}

func (*ErrIPv6ExtensionHeaderProblem) isForwardingError() {}

func (e *ErrIPv6ExtensionHeaderProblem) String() string {
	return fmt.Sprintf("ipv6 extension header problem: %s", e.Err)
}

// IPv6ExtensionHeaderProcessingError represents an error that occured while
// trying to process an IPv6 packet's extension headers.
type IPv6ExtensionHeaderProcessingError interface {
	isIPv6ExtensionHeaderProcessingError()
	fmt.Stringer
}

// ErrMalformedExtensionHeader indicates that the Netstack couldn't correctly
// parse one of the packet's IPv6 extension headers.
type ErrMalformedExtensionHeader struct{}

func (*ErrMalformedExtensionHeader) isIPv6ExtensionHeaderProcessingError() {}

func (*ErrMalformedExtensionHeader) String() string { return "malformed extension header" }

// ErrHopByHopHeaderMisplaced indicates that the packet's Hop-by-Hop extension
// header was found in an incorrect position in the list of extension headers.
type ErrHopByHopHeaderMisplaced struct{}

func (*ErrHopByHopHeaderMisplaced) isIPv6ExtensionHeaderProcessingError() {}

func (*ErrHopByHopHeaderMisplaced) String() string { return "hop-by-hop header misplaced" }

// ErrDuplicateRouterAlertOption indicates that the Netstack found more than
// one Router Alert IPv6 option in the Hop-by-Hop extension header.
type ErrDuplicateRouterAlertOption struct{}

func (*ErrDuplicateRouterAlertOption) isIPv6ExtensionHeaderProcessingError() {}

func (*ErrDuplicateRouterAlertOption) String() string { return "duplicate router alert option" }

// ErrUnrecognizedRoutingType indicates that the packet's routing header contained
// an unrecognized routing type.
type ErrUnrecognizedRoutingType struct{}

func (*ErrUnrecognizedRoutingType) isIPv6ExtensionHeaderProcessingError() {}

func (*ErrUnrecognizedRoutingType) String() string {
	return "routing header with unrecognized routing type and non-zero segments left"
}

// ErrUnknownOptionWithDiscard indicates that the Netstack found an unknown IPv6
// option which had to be discarded as per RFC 8200, Section 4.2.
type ErrUnknownOptionWithDiscard struct{}

func (*ErrUnknownOptionWithDiscard) isIPv6ExtensionHeaderProcessingError() {}

func (*ErrUnknownOptionWithDiscard) String() string { return "unknown option with discard action" }
