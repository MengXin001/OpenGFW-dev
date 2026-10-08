package engine

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func serializeDecap(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	var network gopacket.NetworkLayer
	for _, l := range ls {
		if n, ok := l.(gopacket.NetworkLayer); ok {
			network = n
		}
		if tr, ok := l.(interface {
			SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
		}); ok {
			if err := tr.SetNetworkLayerForChecksum(network); err != nil {
				t.Fatal(err)
			}
		}
	}
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func decapIPv4(protocol layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version: 4, IHL: 5, TTL: 114, Protocol: protocol,
		SrcIP: net.IP{114, 5, 1, 4}, DstIP: net.IP{191, 9, 8, 1},
	}
}

func decapIPv6(protocol layers.IPProtocol) *layers.IPv6 {
	return &layers.IPv6{
		Version: 6, HopLimit: 64, NextHeader: protocol,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
}

func decapEthernet(protocol layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: protocol,
	}
}

func decapUDP() *layers.UDP {
	return &layers.UDP{SrcPort: 11451, DstPort: 65535}
}

func TestDecapProtocols(t *testing.T) {
	inner4 := serializeDecap(t, decapIPv4(layers.IPProtocolUDP), decapUDP(), gopacket.Payload("inner"))
	inner6 := serializeDecap(t, decapIPv6(layers.IPProtocolUDP), decapUDP(), gopacket.Payload("inner"))
	innerEthernet := serializeDecap(t, decapEthernet(layers.EthernetTypeIPv4), gopacket.Payload(inner4))
	innerVLAN := serializeDecap(t, decapEthernet(layers.EthernetTypeDot1Q),
		&layers.Dot1Q{VLANIdentifier: 200, Type: layers.EthernetTypeIPv4}, gopacket.Payload(inner4))
	tests := []struct {
		name     string
		linkType layers.LinkType
		data     []byte
		inner    []byte
		stack    []analyzer.PropMap
	}{
		{name: "raw ipv4", linkType: layers.LinkTypeRaw, data: inner4, inner: inner4},
		{name: "raw ipv6", linkType: layers.LinkTypeRaw, data: inner6, inner: inner6},
		{name: "ethernet", linkType: layers.LinkTypeEthernet, data: innerEthernet, inner: inner4},
		{name: "vlan", linkType: layers.LinkTypeEthernet,
			data: serializeDecap(t, decapEthernet(layers.EthernetTypeDot1Q),
				&layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeIPv4}, gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "vlan", "depth": 0, "vlan_id": uint16(100)}}},
		{name: "qinq", linkType: layers.LinkTypeEthernet,
			data: serializeDecap(t, decapEthernet(layers.EthernetTypeQinQ),
				&layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeDot1Q},
				&layers.Dot1Q{VLANIdentifier: 200, Type: layers.EthernetTypeIPv6}, gopacket.Payload(inner6)), inner: inner6,
			stack: []analyzer.PropMap{{"protocol": "vlan", "depth": 0, "vlan_id": uint16(100)},
				{"protocol": "vlan", "depth": 1, "vlan_id": uint16(200)}}},
		{name: "pppoe ipv4", linkType: layers.LinkTypeEthernet,
			data: serializeDecap(t, decapEthernet(layers.EthernetTypePPPoESession),
				&layers.PPPoE{Version: 1, Type: 1, SessionId: 7}, &layers.PPP{PPPType: layers.PPPTypeIPv4}, gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "pppoe", "depth": 0, "session_id": uint16(7)},
				{"protocol": "ppp", "depth": 1, "ppp_type": layers.PPPTypeIPv4}}},
		{name: "pppoe ipv6", linkType: layers.LinkTypeEthernet,
			data: serializeDecap(t, decapEthernet(layers.EthernetTypePPPoESession),
				&layers.PPPoE{Version: 1, Type: 1, SessionId: 8}, &layers.PPP{PPPType: layers.PPPTypeIPv6}, gopacket.Payload(inner6)), inner: inner6,
			stack: []analyzer.PropMap{{"protocol": "pppoe", "depth": 0, "session_id": uint16(8)},
				{"protocol": "ppp", "depth": 1, "ppp_type": layers.PPPTypeIPv6}}},
		{name: "vxlan", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{SrcPort: 12345, DstPort: 4789},
				&layers.VXLAN{ValidIDFlag: true, VNI: 42}, gopacket.Payload(innerEthernet)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "vxlan", "depth": 0, "vni": uint32(42)}}},
		{name: "vlan vxlan vlan", linkType: layers.LinkTypeEthernet,
			data: serializeDecap(t, decapEthernet(layers.EthernetTypeDot1Q), &layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeIPv6},
				decapIPv6(layers.IPProtocolUDP), &layers.UDP{SrcPort: 12345, DstPort: 4789},
				&layers.VXLAN{ValidIDFlag: true, VNI: 42}, gopacket.Payload(innerVLAN)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "vlan", "depth": 0, "vlan_id": uint16(100)},
				{"protocol": "vxlan", "depth": 1, "vni": uint32(42)}, {"protocol": "vlan", "depth": 2, "vlan_id": uint16(200)}}},
		{name: "gre ipv4", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv4(layers.IPProtocolGRE), &layers.GRE{Protocol: layers.EthernetTypeIPv4, KeyPresent: true, Key: 42}, gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "gre", "depth": 0, "key": uint32(42)}}},
		{name: "gre ethernet", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv6(layers.IPProtocolGRE), &layers.GRE{Protocol: layers.EthernetTypeTransparentEthernetBridging}, gopacket.Payload(innerVLAN)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "gre", "depth": 0}, {"protocol": "vlan", "depth": 1, "vlan_id": uint16(200)}}},
		{name: "mpls stack", linkType: layers.LinkTypeEthernet,
			data: serializeDecap(t, decapEthernet(layers.EthernetTypeMPLSUnicast), &layers.MPLS{Label: 100, TTL: 64},
				&layers.MPLS{Label: 200, TTL: 64, StackBottom: true}, gopacket.Payload(inner6)), inner: inner6,
			stack: []analyzer.PropMap{{"protocol": "mpls", "depth": 0, "label": uint32(100)}, {"protocol": "mpls", "depth": 1, "label": uint32(200)}}},
		{name: "gtpu", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{SrcPort: 12345, DstPort: 2152},
				&layers.GTPv1U{Version: 1, MessageType: 0xff, MessageLength: uint16(len(inner6)), TEID: 42}, gopacket.Payload(inner6)), inner: inner6,
			stack: []analyzer.PropMap{{"protocol": "gtpu", "depth": 0, "teid": uint32(42)}}},
		{name: "ipv4 in ipv4", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv4(layers.IPProtocolIPv4), gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "ipip", "depth": 0}}},
		{name: "ipv6 in ipv4", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv4(layers.IPProtocolIPv6), gopacket.Payload(inner6)), inner: inner6,
			stack: []analyzer.PropMap{{"protocol": "ipip", "depth": 0}}},
		{name: "ipv4 in ipv6", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv6(layers.IPProtocolIPv4), gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "ipip", "depth": 0}}},
		{name: "ipv6 in ipv6", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv6(layers.IPProtocolIPv6), gopacket.Payload(inner6)), inner: inner6,
			stack: []analyzer.PropMap{{"protocol": "ipip", "depth": 0}}},
		{name: "ipv6 destination ipip", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv6(layers.IPProtocolIPv6Destination),
				gopacket.Payload([]byte{4, 0, 0, 0, 0, 0, 0, 0}), gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "ipip", "depth": 0}}},
		{name: "ipv6 hopbyhop ipip", linkType: layers.LinkTypeRaw,
			data: serializeDecap(t, decapIPv6(layers.IPProtocolIPv6HopByHop),
				gopacket.Payload([]byte{4, 0, 0, 0, 0, 0, 0, 0}), gopacket.Payload(inner4)), inner: inner4,
			stack: []analyzer.PropMap{{"protocol": "ipip", "depth": 0}}},
	}
	d := decapDecoder{maxDepth: 8, maxInnerPacketSize: 65535}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Decode(tt.data, tt.linkType)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.Packet.Data(), tt.inner) {
				t.Fatalf("inner packet = %x, want %x", result.Packet.Data(), tt.inner)
			}
			var want analyzer.PropMap
			if len(tt.stack) > 0 {
				want = analyzer.PropMap{"stack": tt.stack}
			}
			if !reflect.DeepEqual(result.Encap, want) {
				t.Fatalf("encap = %#v, want %#v", result.Encap, want)
			}
			if result.Packet.TransportLayer() == nil {
				t.Fatal("inner transport layer missing")
			}
		})
	}
}

func TestDecapInvalidPackets(t *testing.T) {
	inner := serializeDecap(t, decapIPv4(layers.IPProtocolUDP), decapUDP(), gopacket.Payload("inner"))
	vlan := serializeDecap(t, decapEthernet(layers.EthernetTypeDot1Q),
		&layers.Dot1Q{Type: layers.EthernetTypeDot1Q}, &layers.Dot1Q{Type: layers.EthernetTypeIPv4}, gopacket.Payload(inner))
	vxlan := serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{DstPort: 4789},
		&layers.VXLAN{ValidIDFlag: true}, decapEthernet(layers.EthernetTypeIPv4), gopacket.Payload(inner))
	pppoe := serializeDecap(t, decapEthernet(layers.EthernetTypePPPoESession),
		&layers.PPPoE{Version: 1, Type: 1, SessionId: 1}, &layers.PPP{PPPType: layers.PPPTypeIPv4}, gopacket.Payload(inner))
	gtpu := serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{DstPort: 2152},
		&layers.GTPv1U{Version: 1, MessageType: 0xff, MessageLength: uint16(len(inner))}, gopacket.Payload(inner))
	mutate := func(data []byte, offset int, value byte) []byte {
		data = bytes.Clone(data)
		data[offset] = value
		return data
	}
	tests := []struct {
		name     string
		data     []byte
		linkType layers.LinkType
		depth    int
		size     int
	}{
		{name: "empty", linkType: layers.LinkTypeRaw},
		{name: "short ip", data: inner[:19], linkType: layers.LinkTypeRaw},
		{name: "truncated ip payload", data: inner[:len(inner)-1], linkType: layers.LinkTypeRaw},
		{name: "zero ip length", data: mutate(mutate(inner, 2, 0), 3, 0), linkType: layers.LinkTypeRaw},
		{name: "unknown link", data: inner, linkType: layers.LinkType(255)},
		{name: "unknown ethernet", data: serializeDecap(t, decapEthernet(layers.EthernetTypeARP), gopacket.Payload(inner)), linkType: layers.LinkTypeEthernet},
		{name: "truncated vlan", data: vlan[:16], linkType: layers.LinkTypeEthernet},
		{name: "depth exceeded", data: vlan, linkType: layers.LinkTypeEthernet, depth: 1},
		{name: "size exceeded", data: inner, linkType: layers.LinkTypeRaw, size: len(inner) - 1},
		{name: "vxlan missing id flag", data: mutate(vxlan, 28, 0), linkType: layers.LinkTypeRaw},
		{name: "vxlan truncated", data: vxlan[:35], linkType: layers.LinkTypeRaw},
		{name: "vxlan missing inner", data: serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{DstPort: 4789}, &layers.VXLAN{ValidIDFlag: true}), linkType: layers.LinkTypeRaw},
		{name: "udp invalid length", data: mutate(vxlan, 24, 0xff), linkType: layers.LinkTypeRaw},
		{name: "pppoe invalid version", data: mutate(pppoe, 14, 0x21), linkType: layers.LinkTypeEthernet},
		{name: "pppoe zero session", data: mutate(pppoe, 17, 0), linkType: layers.LinkTypeEthernet},
		{name: "pppoe excessive length", data: mutate(pppoe, 18, 0xff), linkType: layers.LinkTypeEthernet},
		{name: "pppoe discovery", data: mutate(pppoe, 15, 9), linkType: layers.LinkTypeEthernet},
		{name: "gtpu invalid version", data: mutate(gtpu, 28, 0x50), linkType: layers.LinkTypeRaw},
		{name: "gtpu invalid type", data: mutate(gtpu, 29, 1), linkType: layers.LinkTypeRaw},
		{name: "gtpu invalid length", data: mutate(gtpu, 30, 0xff), linkType: layers.LinkTypeRaw},
		{name: "gre invalid version", data: serializeDecap(t, decapIPv4(layers.IPProtocolGRE), &layers.GRE{Version: 1, Protocol: layers.EthernetTypeIPv4}, gopacket.Payload(inner)), linkType: layers.LinkTypeRaw},
		{name: "gre unknown protocol", data: serializeDecap(t, decapIPv4(layers.IPProtocolGRE), &layers.GRE{Protocol: layers.EthernetTypeARP}, gopacket.Payload(inner)), linkType: layers.LinkTypeRaw},
		{name: "mpls missing bottom", data: serializeDecap(t, decapEthernet(layers.EthernetTypeMPLSUnicast), &layers.MPLS{Label: 1}, gopacket.Payload(inner)), linkType: layers.LinkTypeEthernet},
		{name: "ipv4 first fragment", data: mutate(inner, 6, 0x20), linkType: layers.LinkTypeRaw},
		{name: "ipv4 later fragment", data: mutate(inner, 7, 1), linkType: layers.LinkTypeRaw},
		{name: "ipv6 fragment", data: serializeDecap(t, decapIPv6(layers.IPProtocolIPv6Fragment), gopacket.Payload([]byte{17, 0, 0, 1, 0, 0, 0, 0}), gopacket.Payload(inner)), linkType: layers.LinkTypeRaw},
		{name: "geneve unsupported", data: serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{DstPort: 6081}, gopacket.Payload(inner)), linkType: layers.LinkTypeRaw},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := decapDecoder{maxDepth: 8, maxInnerPacketSize: 65535}
			if tt.depth > 0 {
				d.maxDepth = tt.depth
			}
			if tt.size > 0 {
				d.maxInnerPacketSize = tt.size
			}
			if _, err := d.Decode(tt.data, tt.linkType); err == nil {
				t.Fatal("invalid packet accepted by decoder")
			}
		})
	}
	if _, err := (&decapDecoder{maxDepth: 2, maxInnerPacketSize: len(inner)}).Decode(vlan, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("exact depth and size limits: %v", err)
	}
}

func TestDecapApplicationError(t *testing.T) {
	data := serializeDecap(t, decapIPv4(layers.IPProtocolUDP), &layers.UDP{DstPort: 53}, gopacket.Payload("bad"))
	result, err := (&decapDecoder{maxDepth: 8, maxInnerPacketSize: 65535}).Decode(data, layers.LinkTypeRaw)
	if err != nil || result.Packet.TransportLayer() == nil {
		t.Fatalf("application decode failure rejected transport: %v", err)
	}
}

func FuzzDecapDecoder(f *testing.F) {
	f.Add([]byte{}, uint8(layers.LinkTypeRaw))
	f.Add([]byte{0x45}, uint8(layers.LinkTypeEthernet))
	f.Add([]byte{0x60}, uint8(layers.LinkTypeRaw))
	f.Fuzz(func(t *testing.T, data []byte, linkType uint8) {
		d := decapDecoder{maxDepth: 8, maxInnerPacketSize: 65535}
		result, err := d.Decode(data, layers.LinkType(linkType))
		if err == nil && (result.Packet == nil || len(result.Packet.Data()) == 0) {
			t.Fatal("decoder returned an empty packet")
		}
	})
}
