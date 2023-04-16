package protodef_test

import (
	"fmt"
	"testing"

	"github.com/blorticus-go/protodef"
)

func TestMarshallIPv4Packet(t *testing.T) {
	for _, testCase := range []*MarshallIPv4PacketTestCase{
		{
			Name: "Marshall Well-Formed IP Packet 01",
			PacketStruct: &protodef.IPv4Packet{
				Header: protodef.IPv4PacketHeader{
					Version:            4,
					HeaderLength:       5,
					DSCP:               0,
					ECN:                0,
					TotalPacketLength:  84,
					FragmentIdentifier: 0x7686,
					Flags:              0x2,
					FragmentOffset:     0,
					TTL:                64,
					Protocol:           0x1,
					HeaderChecksum:     0x5295,
					SourceAddress:      0xac145e99,
					DestinationAddress: 0x8efbd7e4,
				},
				Data: []byte{
					0x08, 0x00, 0x37, 0x6e, 0x12, 0xb2, 0x00, 0x01,
					0x1b, 0x6f, 0x3c, 0x64, 0x00, 0x00, 0x00, 0x00,
					0x8f, 0x38, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
					0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
				},
			},
			ExpectedBytes: []byte{
				0x45, 0x00, 0x00, 0x54, 0x76, 0x86, 0x40, 0x00, 0x40, 0x01, 0x52, 0x95, 0xac, 0x14, 0x5e, 0x99,
				0x8e, 0xfb, 0xd7, 0xe4, 0x08, 0x00, 0x37, 0x6e, 0x12, 0xb2, 0x00, 0x01, 0x1b, 0x6f, 0x3c, 0x64,
				0x00, 0x00, 0x00, 0x00, 0x8f, 0x38, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13,
				0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
				0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
				0x34, 0x35, 0x36, 0x37,
			},
		},
	} {
		if err := testCase.RunTest(); err != nil {
			t.Errorf("[%s]: %s", testCase.Name, err.Error())
		}
	}
}

// 45 00 00 54 76 86 40 00 40 01 52 95 ac 14 5e 99 8e fb d7 e4

type MarshallIPv4PacketTestCase struct {
	Name          string
	PacketStruct  *protodef.IPv4Packet
	ExpectedBytes []byte
	ExpectAnError bool
}

func (testCase *MarshallIPv4PacketTestCase) RunTest() error {
	marshalledBytes, err := protodef.MarshallIPv4Packet(testCase.PacketStruct)
	if err != nil {
		if !testCase.ExpectAnError {
			return fmt.Errorf("did not expect an error, but got: %s", err.Error())
		} else {
			return nil
		}
	}

	if len(marshalledBytes) != len(testCase.ExpectedBytes) {
		return fmt.Errorf("expected (%d) bytes, got (%d)", len(testCase.ExpectedBytes), len(marshalledBytes))
	}

	for byteOffset, marshalledByte := range marshalledBytes {
		if marshalledByte != testCase.ExpectedBytes[byteOffset] {
			return fmt.Errorf("bytes start to differ at offset (%d), expected byte = (0x%02x), got = (0x%02x)", byteOffset, testCase.ExpectedBytes[byteOffset], marshalledByte)
		}
	}

	return nil
}
