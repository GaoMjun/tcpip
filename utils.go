package tcpip

import (
	"fmt"
	"net"
)

func InetNtoA(ip int) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func InetAtoN(ip string) int {
	ipBytes := net.ParseIP(ip).To4()
	return int(ipBytes[0])<<24 | int(ipBytes[1])<<16 | int(ipBytes[2])<<8 | int(ipBytes[3])
}

func checksum(data []byte, csum uint32) uint16 {
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}
