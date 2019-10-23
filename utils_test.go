package tcpip

import (
	"encoding/hex"
	"log"
	"testing"
)

func TestChecksum(t *testing.T) {

	bs, _ := hex.DecodeString("45000054ce040000400100000a00000b0a000001")
	sum := checksum(bs, 0)

	log.Println(sum)
}
