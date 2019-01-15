package tcpip

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestICMP(t *testing.T) {
	packet := Packet{}

	packet.Raw, _ = hex.DecodeString("45000054A86D4000400199450A01000A7B7D736E0800051B346B0001F9943D5C00000000C7B4010000000000101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233342170437")

	log.Println(packet)
}

func TestTCP(t *testing.T) {
	packet := Packet{}
	packet.Raw, _ = hex.DecodeString("4500003C59DC40004006E7E97B7D736E0A01000AE91E22B83CDAFCAE00000000A0027210AF670000020405B40402080A9DA196F20000000001030307")

	packet.ComputeAllChecksum()
	log.Println(hex.EncodeToString(packet.Raw))
}

func TestUDP(t *testing.T) {
	packet := Packet{}

	log.Println(packet)
}
