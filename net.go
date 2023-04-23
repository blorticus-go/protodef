package protodef

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	IPv4FlagDontFragment  uint8 = 0x01
	IPv4FlagMoreFragments uint8 = 0x02
)

// IPv4PacketHeader represents the values of an IPv4 packet header.
type IPv4PacketHeader struct {
	Version                   uint8
	HeaderLengthInDoubleWords uint8
	DSCP                      uint8
	ECN                       uint8
	TotalPacketLengthInBytes  uint16
	FragmentIdentifier        uint16
	Flags                     uint8
	FragmentOffset            uint16
	TTL                       uint8
	Protocol                  IPProtocol
	HeaderChecksum            uint16
	SourceAddress             net.IP
	DestinationAddress        net.IP
}

// IPv4Packet represents a complete IPv4 packet.  The Options must already be
// in BigEndian format.
type IPv4Packet struct {
	Header           IPv4PacketHeader
	Options          []byte
	NumberOfPadBytes uint8
	Data             []byte
	pdu              IPProtocolPDU
}

func cloneIP(src *net.IP) net.IP {
	clone := make([]byte, len([]byte(*src)))
	return net.IP(clone)
}

func NewIPv4Packet(source *net.IP, destination *net.IP) *IPv4Packet {
	return &IPv4Packet{
		Header: IPv4PacketHeader{
			Version:                   4,
			HeaderLengthInDoubleWords: 5,
			TotalPacketLengthInBytes:  20,
			TTL:                       64,
			SourceAddress:             cloneIP(source),
			DestinationAddress:        cloneIP(destination),
		},
	}
}

func (packet *IPv4Packet) SetRawPayloadErrorable(payloadInNetworkByteOrder []byte, ipPacketProtocolFieldValue IPProtocol) error {
	if len(payloadInNetworkByteOrder) > 65536-(int(packet.Header.HeaderLengthInDoubleWords)*4) {
		return fmt.Errorf("payload is too long")
	}

	packet.Header.Protocol = ipPacketProtocolFieldValue
	packet.Data = payloadInNetworkByteOrder

	return nil
}

func (packet *IPv4Packet) WithPayloadFromPdu(pdu IPProtocolPDU) *IPv4Packet {
	packet.pdu = pdu
	return packet
}

func (packet *IPv4Packet) WithRawPayload(payloadInNetworkByteOrder []byte, ipPacketProtocolFieldValue IPProtocol) *IPv4Packet {
	if err := packet.SetRawPayloadErrorable(payloadInNetworkByteOrder, ipPacketProtocolFieldValue); err != nil {
		panic(err.Error())
	}

	return packet
}

func (packet *IPv4Packet) ComputeHeaderChecksum() uint16 {
	srcIPAsUint32 := binary.BigEndian.Uint32(packet.Header.SourceAddress.To4())
	destIPAsUint32 := binary.BigEndian.Uint32(packet.Header.DestinationAddress.To4())

	sum := uint32((uint32(packet.Header.Version)<<12)|(uint32(packet.Header.HeaderLengthInDoubleWords)<<8)|(uint32(packet.Header.DSCP)<<2)|(0x03&uint32(packet.Header.ECN))) +
		uint32(packet.Header.TotalPacketLengthInBytes) +
		uint32(packet.Header.FragmentIdentifier) +
		uint32(uint32(packet.Header.Flags)<<13) | (uint32(packet.Header.FragmentOffset) & 0x1fff) +
		(uint32(packet.Header.TTL) << 8) | uint32(packet.Header.Protocol) +
		(srcIPAsUint32 >> 16) +
		(srcIPAsUint32 & 0x0000ffff) +
		(destIPAsUint32 >> 16) +
		(destIPAsUint32 & 0x0000ffff)

	for sum > 0xffff {
		hi16 := (sum & 0xffff0000) >> 16
		sum = (sum & 0xffff) + hi16
	}

	return uint16(0xffff - sum)
}

func validateIPv4PacketStruct(packet *IPv4Packet) error {
	if packet.Header.Version != 4 {
		return fmt.Errorf("invalid Version (%d)", packet.Header.Version)
	}

	if packet.Header.HeaderLengthInDoubleWords > 15 {
		return fmt.Errorf("invalid HeaderLength (%d)", packet.Header.HeaderLengthInDoubleWords)
	}

	if packet.Header.DSCP > 63 {
		return fmt.Errorf("invalid DSCP (0x%02x)", packet.Header.DSCP)
	}

	if packet.Header.ECN > 3 {
		return fmt.Errorf("invalid ECN (0x%x)", packet.Header.ECN)
	}

	if packet.Header.Flags&0x09 != 0 {
		return fmt.Errorf("invalid Flags (0x%x)", packet.Header.Flags)
	}

	if len(packet.Options) > 40 {
		return fmt.Errorf("options too long")
	}

	encodedHeaderLength := 20 + len(packet.Options) + int(packet.NumberOfPadBytes)

	if int(packet.Header.HeaderLengthInDoubleWords)*4 != 20+len(packet.Options)+int(packet.NumberOfPadBytes) {
		return fmt.Errorf("header length of (%d) bytes does not match fixed header length (20) plus options (%d) and padding (%d)", packet.Header.HeaderLengthInDoubleWords*4, len(packet.Options), packet.NumberOfPadBytes)
	}

	if int(packet.Header.TotalPacketLengthInBytes) != encodedHeaderLength+len(packet.Data) {
		return fmt.Errorf("total packet length header value (%d) does not match total encoded packet length (%d)", packet.Header.TotalPacketLengthInBytes, encodedHeaderLength+len(packet.Data))
	}

	return nil
}

// Marshall creates a wire-representation (in network byte order) of an IPv4Packet
// struct.  If any field contains an illegal value, an error is returned.  No check is made
// for a valid Protocol value, a correct Checksum or valid Options.
func (packet *IPv4Packet) Marshall() ([]byte, error) {
	if packet.Data == nil {
		if packet.pdu != nil {
			data, err := packet.pdu.MarshallToNetworkByteOrder()
			if err != nil {
				return nil, fmt.Errorf("unable to unmarshall IP packet PDU: %s", err.Error())
			}
			packet.Data = data
		}
	}

	totalLengthUint32 := uint32(packet.Header.HeaderLengthInDoubleWords)*4 + uint32(len(packet.Data))

	if totalLengthUint32 > 0xffff {
		return nil, fmt.Errorf("encoded length (%d) exceeds maximum IPv4 packet length", totalLengthUint32)
	}

	packet.Header.TotalPacketLengthInBytes = uint16(totalLengthUint32)

	if err := validateIPv4PacketStruct(packet); err != nil {
		return nil, err
	}

	packet.Header.HeaderChecksum = packet.ComputeHeaderChecksum()

	marshalled := make([]byte, 20+len(packet.Options)+int(packet.NumberOfPadBytes)+len(packet.Data))

	marshalled[0] = 0x40 | packet.Header.HeaderLengthInDoubleWords
	marshalled[1] = (packet.Header.DSCP << 2) | (packet.Header.ECN & 0x03)
	binary.BigEndian.PutUint16(marshalled[2:4], packet.Header.TotalPacketLengthInBytes)
	binary.BigEndian.PutUint16(marshalled[4:6], packet.Header.FragmentIdentifier)
	binary.BigEndian.PutUint16(marshalled[6:8], ((uint16(packet.Header.Flags) << 13) | (uint16(packet.Header.FragmentOffset) & 0x03f)))
	marshalled[8] = packet.Header.TTL
	marshalled[9] = byte(packet.Header.Protocol)
	binary.BigEndian.PutUint16(marshalled[10:12], packet.Header.HeaderChecksum)
	copy(marshalled[12:16], packet.Header.SourceAddress.To4()[:4])
	copy(marshalled[16:20], packet.Header.DestinationAddress.To4()[:4])
	copy(marshalled[20:20+len(packet.Options)], packet.Options)

	offset := 20 + len(packet.Options)
	for i := 0; i < int(packet.NumberOfPadBytes); i++ {
		marshalled[offset+i] = 0
	}

	copy(marshalled[offset+int(packet.NumberOfPadBytes):], packet.Data)

	return marshalled, nil
}

// MarshallToNetworkByteOrder is synonymous with Marshall() but satisfies
// the NetworkByteOrderPDU interface.
func (packet *IPv4Packet) MarshallToNetworkByteOrder() ([]byte, error) {
	return packet.Marshall()
}

func (packet *IPv4Packet) IPProtocolValue() IPProtocol {
	return IPProtoIPIP
}

func UnmarshallIPv4Packet(asBytes []byte) (*IPv4Packet, error) {
	return nil, nil
}

type ICMPv4Type uint8

const (
	ICMPv4EchoReply              ICMPv4Type = 0
	ICMPv4DestinationUnreachable ICMPv4Type = 3
	ICMPv4SourceQuench           ICMPv4Type = 4
	ICMPv4Redirect               ICMPv4Type = 5
	ICMPv4EchoRequest            ICMPv4Type = 8
	ICMPv4RouterAdvertisement    ICMPv4Type = 9
	ICMPv4RouterSolicitation     ICMPv4Type = 10
	ICMPv4TimeExceeded           ICMPv4Type = 11
	ICMPv4BadIPHeader            ICMPv4Type = 12
	ICMPv4Timestamp              ICMPv4Type = 13
	ICMPv4TimestampReply         ICMPv4Type = 14
	ICMPv4ExtendedEchoRequest    ICMPv4Type = 42
	ICMPv4ExtendedEchoReply      ICMPv4Type = 43
)

type ICMPv4Header struct {
	Type               ICMPv4Type
	Code               uint8
	Checksum           uint16
	TypeSpecificHeader []byte
}

type ICMPv4PDU struct {
	Header ICMPv4Header
	Data   []byte
}

// Marshall converts the data structure values into wire format (in network byte order).
// None of the fields are checked for correctness.
func (pdu *ICMPv4PDU) Marshall() ([]byte, error) {
	marshalled := make([]byte, 4+len(pdu.Header.TypeSpecificHeader)+len(pdu.Data))

	marshalled[0] = uint8(pdu.Header.Type)
	marshalled[1] = pdu.Header.Code
	binary.BigEndian.PutUint16(marshalled[2:4], pdu.Header.Checksum)
	copy(marshalled[4:len(pdu.Header.TypeSpecificHeader)], pdu.Header.TypeSpecificHeader)

	offset := 4 + len(pdu.Header.TypeSpecificHeader)
	copy(marshalled[offset:], pdu.Data)

	return marshalled, nil
}

// MarshallToNetworkByteOrder is synonymous with Marshall() but satisfies
// the NetworkByteOrderPDU interface.
func (pdu *ICMPv4PDU) MarshallToNetworkByteOrder() ([]byte, error) {
	return pdu.Marshall()
}

func (pdu *ICMPv4PDU) IPProtocolValue() IPProtocol {
	return IPProtoICMP
}

func UnmarshallICMPv4PDU(asBytes []byte) (*ICMPv4PDU, error) {
	return nil, nil
}
