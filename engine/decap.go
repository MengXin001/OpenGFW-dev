package engine

import (
	"encoding/binary"
	"errors"

	"github.com/apernet/OpenGFW/analyzer"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	defaultDecapMaxDepth           = 8
	defaultDecapMaxInnerPacketSize = 65535
)

var (
	errInvalidDecapPacket = errors.New("invalid encapsulated packet")
	errDecapDepthExceeded = errors.New("encapsulation depth exceeded")
)

type decapDecoder struct {
	enabled            bool
	maxDepth           int
	maxInnerPacketSize int
}

type decapResult struct {
	Packet gopacket.Packet
	Encap  analyzer.PropMap
}

type decapPacketBuilder struct {
	gopacket.PacketBuilder
	next gopacket.Decoder
}

func (p *decapPacketBuilder) NextDecoder(next gopacket.Decoder) error {
	p.next = next
	return nil
}

func decodeDecapLayer(data []byte, decoder gopacket.Decoder) (gopacket.Packet, gopacket.Decoder) {
	var builder *decapPacketBuilder
	packet := gopacket.NewPacket(data, gopacket.DecodeFunc(func(data []byte, p gopacket.PacketBuilder) error {
		builder = &decapPacketBuilder{PacketBuilder: p}
		return decoder.Decode(data, builder)
	}), gopacket.DecodeOptions{NoCopy: true})
	return packet, builder.next
}

func (d *decapDecoder) Decode(data []byte, linkType layers.LinkType) (decapResult, error) {
	var decoder gopacket.Decoder = linkType
	var ipData []byte
	var ipType gopacket.LayerType
	var stack []analyzer.PropMap
	finish := func() (decapResult, error) {
		if len(ipData) == 0 || len(ipData) > d.maxInnerPacketSize {
			return decapResult{}, errInvalidDecapPacket
		}
		result := decapResult{
			Packet: gopacket.NewPacket(ipData, ipType, gopacket.DecodeOptions{Lazy: true, NoCopy: true}),
		}
		if len(stack) > 0 {
			result.Encap = analyzer.PropMap{"stack": stack}
		}
		return result, nil
	}
	for {
		if len(data) == 0 || decoder == nil {
			return decapResult{}, errInvalidDecapPacket
		}
		packet, next := decodeDecapLayer(data, decoder)
		if packet.ErrorLayer() != nil || len(packet.Layers()) == 0 {
			return decapResult{}, errInvalidDecapPacket
		}
		layer := packet.Layers()[0]
		payload := layer.LayerPayload()
		var entry analyzer.PropMap
		switch l := layer.(type) {
		case *layers.Ethernet, *layers.LinuxSLL, *layers.Loopback:
		case *layers.Dot1Q:
			entry = analyzer.PropMap{"protocol": "vlan", "vlan_id": l.VLANIdentifier}
		case *layers.PPPoE:
			if l.Version != 1 || l.Type != 1 || l.Code != layers.PPPoECodeSession || l.SessionId == 0 {
				return decapResult{}, errInvalidDecapPacket
			}
			entry = analyzer.PropMap{"protocol": "pppoe", "session_id": l.SessionId}
		case *layers.PPP:
			if l.PPPType != layers.PPPTypeIPv4 && l.PPPType != layers.PPPTypeIPv6 {
				return decapResult{}, errInvalidDecapPacket
			}
			entry = analyzer.PropMap{"protocol": "ppp", "ppp_type": l.PPPType}
		case *layers.MPLS:
			entry = analyzer.PropMap{"protocol": "mpls", "label": l.Label}
		case *layers.IPv4:
			if l.Version != 4 || binary.BigEndian.Uint16(data[2:4]) == 0 ||
				int(l.Length) > len(data) || l.FragOffset != 0 || l.Flags&layers.IPv4MoreFragments != 0 {
				return decapResult{}, errInvalidDecapPacket
			}
			ipData, ipType = data[:l.Length], layers.LayerTypeIPv4
			switch l.Protocol {
			case layers.IPProtocolIPv4, layers.IPProtocolIPv6:
				entry = analyzer.PropMap{"protocol": "ipip"}
			case layers.IPProtocolUDP, layers.IPProtocolGRE:
			default:
				return finish()
			}
		case *layers.IPv6:
			length := 40 + int(l.Length)
			if l.Version != 6 || l.Length == 0 || length > len(data) {
				return decapResult{}, errInvalidDecapPacket
			}
			ipData, ipType = data[:length], layers.LayerTypeIPv6
			if l.HopByHop != nil {
				offset := 40 + l.HopByHop.ActualLength
				if offset > length {
					return decapResult{}, errInvalidDecapPacket
				}
				payload = ipData[offset:]
			}
			switch l.NextLayerType() {
			case layers.LayerTypeIPv4, layers.LayerTypeIPv6:
				entry = analyzer.PropMap{"protocol": "ipip"}
			case layers.LayerTypeUDP, layers.LayerTypeGRE, layers.LayerTypeIPv6Routing,
				layers.LayerTypeIPv6Destination, layers.LayerTypeIPv6Fragment:
			default:
				return finish()
			}
		case *layers.IPv6Routing:
			if l.NextHeader == layers.IPProtocolIPv4 || l.NextHeader == layers.IPProtocolIPv6 {
				entry = analyzer.PropMap{"protocol": "ipip"}
			}
		case *layers.IPv6Destination:
			if l.NextHeader == layers.IPProtocolIPv4 || l.NextHeader == layers.IPProtocolIPv6 {
				entry = analyzer.PropMap{"protocol": "ipip"}
			}
		case *layers.IPv6Fragment:
			return decapResult{}, errInvalidDecapPacket
		case *layers.UDP:
			if l.Length < 8 || int(l.Length) > len(data) {
				return decapResult{}, errInvalidDecapPacket
			}
			switch l.NextLayerType() {
			case layers.LayerTypeVXLAN, layers.LayerTypeGTPv1U:
			case layers.LayerTypeGeneve:
				return decapResult{}, errInvalidDecapPacket
			default:
				return finish()
			}
		case *layers.GRE:
			if l.Version != 0 || l.Flags != 0 || l.AckPresent || l.RecursionControl != 0 {
				return decapResult{}, errInvalidDecapPacket
			}
			switch l.Protocol {
			case layers.EthernetTypeIPv4, layers.EthernetTypeIPv6, layers.EthernetTypeTransparentEthernetBridging,
				layers.EthernetTypeMPLSUnicast, layers.EthernetTypeMPLSMulticast:
			default:
				return decapResult{}, errInvalidDecapPacket
			}
			entry = analyzer.PropMap{"protocol": "gre"}
			if l.KeyPresent {
				entry["key"] = l.Key
			}
		case *layers.VXLAN:
			if !l.ValidIDFlag {
				return decapResult{}, errInvalidDecapPacket
			}
			entry = analyzer.PropMap{"protocol": "vxlan", "vni": l.VNI}
		case *layers.GTPv1U:
			length := 8 + int(l.MessageLength)
			if l.Version != 1 || l.ProtocolType != 1 || l.MessageType != 0xff ||
				length > len(data) || length < len(l.LayerContents()) {
				return decapResult{}, errInvalidDecapPacket
			}
			payload = data[len(l.LayerContents()):length]
			entry = analyzer.PropMap{"protocol": "gtpu", "teid": l.TEID}
		case *layers.TCP, *layers.ICMPv4, *layers.ICMPv6:
			return finish()
		default:
			return decapResult{}, errInvalidDecapPacket
		}
		if packet.Metadata().Truncated {
			if l, ok := layer.(*layers.IPv6); !ok || l.HopByHop == nil {
				return decapResult{}, errInvalidDecapPacket
			}
		}
		if entry != nil {
			if len(stack) >= d.maxDepth {
				return decapResult{}, errDecapDepthExceeded
			}
			entry["depth"] = len(stack)
			stack = append(stack, entry)
		}
		if len(payload) >= len(data) {
			return decapResult{}, errInvalidDecapPacket
		}
		data, decoder = payload, next
	}
}

func innerStreamID(parent uint32, ipFlow, transportFlow gopacket.Flow) uint32 {
	h := ipFlow.FastHash() ^ transportFlow.FastHash() ^ uint64(parent)*0x9e3779b1
	return uint32(h) ^ uint32(h>>32)
}
