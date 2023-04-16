package protodef

import (
	"encoding/binary"
	"fmt"
)

const (
	IPv4FlagDontFragment  uint8 = 0x01
	IPv4FlagMoreFragments uint8 = 0x02
)

// IPv4PacketHeader represents the values of an IPv4 packet header.
type IPv4PacketHeader struct {
	Version            uint8
	HeaderLength       uint8
	DSCP               uint8
	ECN                uint8
	TotalPacketLength  uint16
	FragmentIdentifier uint16
	Flags              uint8
	FragmentOffset     uint16
	TTL                uint8
	Protocol           uint8
	HeaderChecksum     uint16
	SourceAddress      uint32
	DestinationAddress uint32
}

// IPv4Packet represents a complete IPv4 packet.  The Options must already be
// in BigEndian format.
type IPv4Packet struct {
	Header           IPv4PacketHeader
	Options          []byte
	NumberOfPadBytes uint8
	Data             []byte
}

func validateIPv4PacketStruct(packet *IPv4Packet) error {
	if packet.Header.Version != 4 {
		return fmt.Errorf("invalid Version (%d)", packet.Header.Version)
	}

	if packet.Header.HeaderLength > 15 {
		return fmt.Errorf("invalid HeaderLength (%d)", packet.Header.HeaderLength)
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

	if int(packet.Header.HeaderLength)*4 != 20+len(packet.Options)+int(packet.NumberOfPadBytes) {
		return fmt.Errorf("header length of (%d) bytes does not match fixed header length (20) plus options (%d) and padding (%d)", packet.Header.HeaderLength*4, len(packet.Options), packet.NumberOfPadBytes)
	}

	if int(packet.Header.TotalPacketLength) != encodedHeaderLength+len(packet.Data) {
		return fmt.Errorf("total packet length header value (%d) does not match total encoded packet length (%d)", packet.Header.TotalPacketLength, encodedHeaderLength+len(packet.Data))
	}

	return nil
}

// MarshallIPv4Packet creates a wire-representation (in network byte order) of an IPv4Packet
// struct.  If any field contains an illegal value, an error is returned.  No check is made
// for a valid Protocol value, a correct Checksum or valid Options.
func MarshallIPv4Packet(packet *IPv4Packet) ([]byte, error) {
	if err := validateIPv4PacketStruct(packet); err != nil {
		return nil, err
	}

	marshalled := make([]byte, 20+len(packet.Options)+int(packet.NumberOfPadBytes)+len(packet.Data))

	marshalled[0] = 0x40 | packet.Header.HeaderLength
	marshalled[1] = (packet.Header.DSCP << 2) | (packet.Header.ECN & 0x03)
	binary.BigEndian.PutUint16(marshalled[2:4], packet.Header.TotalPacketLength)
	binary.BigEndian.PutUint16(marshalled[4:6], packet.Header.FragmentIdentifier)
	binary.BigEndian.PutUint16(marshalled[6:8], ((uint16(packet.Header.Flags) << 13) | (uint16(packet.Header.FragmentOffset) & 0x03f)))
	marshalled[8] = packet.Header.TTL
	marshalled[9] = packet.Header.Protocol
	binary.BigEndian.PutUint16(marshalled[10:12], packet.Header.HeaderChecksum)
	binary.BigEndian.PutUint32(marshalled[12:16], packet.Header.SourceAddress)
	binary.BigEndian.PutUint32(marshalled[16:20], packet.Header.DestinationAddress)
	copy(marshalled[20:20+len(packet.Options)], packet.Options)

	offset := 20 + len(packet.Options)
	for i := 0; i < int(packet.NumberOfPadBytes); i++ {
		marshalled[offset+i] = 0
	}

	copy(marshalled[offset+int(packet.NumberOfPadBytes):], packet.Data)

	return marshalled, nil
}

func UnmarshallIPv4Packet(asBytes []byte) (*IPv4Packet, error) {
	return nil, nil
}
