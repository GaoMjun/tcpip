package tcpip

import "fmt"

type VERSION int

const (
	IPv4 VERSION = 4
	IPv6 VERSION = 6
)

type Packet struct {
	Raw []byte
}

func (self Packet) Version() VERSION {
	return VERSION(self.Raw[0] >> 4)
}

func (self Packet) String() (s string) {
	switch self.Version() {
	case IPv4:
		s += "IPv4 "

		switch self.Protocol() {
		case ICMP:
			s += fmt.Sprintf("ICMP %s->%s",
				InetNtoA(self.SourceIPAddress()), InetNtoA(self.DestinationIPAddress()))
		case TCP:
			s += fmt.Sprintf("TCP %s:%d->%s:%d",
				InetNtoA(self.SourceIPAddress()), self.SourcePort(),
				InetNtoA(self.DestinationIPAddress()), self.DestinationPort())
		case UDP:
			s += fmt.Sprintf("UDP %s:%d->%s:%d",
				InetNtoA(self.SourceIPAddress()), self.SourcePort(),
				InetNtoA(self.DestinationIPAddress()), self.DestinationPort())
		default:
			s += "not support porotocol "
		}

	case IPv6:
		s += "IPv6 "
	default:
		s += "not support porotocol "
	}
	return
}

func (self Packet) ComputeAllChecksum() {
	sum := self.computeIPChecksum()
	self.SetHeaderChecksum(int(sum))

	if self.Version() == IPv4 {
		if self.Protocol() == TCP {
			sum = self.computeTCPChecksum()
			self.SetTCPChecksum(int(sum))
			return
		}

		if self.Protocol() == UDP {
			sum = self.computeUDPChecksum()
			self.SetUDPChecksum(int(sum))
			return
		}
	}

	if self.Version() == IPv6 {
		if self.NextHeader() == TCP {
			sum = self.computeTCPChecksum()
			self.SetTCPChecksum(int(sum))
			return
		}

		if self.NextHeader() == UDP {
			sum = self.computeUDPChecksum()
			self.SetUDPChecksum(int(sum))
			return
		}
	}
}

func (self Packet) computeIPChecksum() uint16 {
	self.SetHeaderChecksum(0)
	return checksum(self.Raw[:self.IHL()], 0)
}

func (self Packet) computeTCPChecksum() uint16 {
	self.SetTCPChecksum(0)

	length := self.TotalLength() - self.IHL()

	csum := self.pseudoheaderChecksum()
	csum += uint32(TCP)
	csum += uint32(length & 0xFFFF)
	csum += uint32(length >> 16)

	return checksum(self.Raw[self.IHL():self.TotalLength()], csum)
}

func (self Packet) computeUDPChecksum() uint16 {
	return 0
}

func (self Packet) pseudoheaderChecksum() (csum uint32) {
	if self.Version() == IPv4 {
		ip := self.SourceIPAddress()
		csum += uint32(ip >> 16)
		csum += uint32(ip & 0xFFFF)

		ip = self.DestinationIPAddress()
		csum += uint32(ip >> 16)
		csum += uint32(ip & 0xFFFF)

		return
	}

	if self.Version() == IPv6 {
		ip := self.SourceAddress()
		csum += uint32(ip >> 48 & 0xFFFF)
		csum += uint32(ip >> 32 & 0xFFFF)
		csum += uint32(ip >> 16 & 0xFFFF)
		csum += uint32(ip >> 0 & 0xFFFF)

		ip = self.DestinationAddress()
		csum += uint32(ip >> 48 & 0xFFFF)
		csum += uint32(ip >> 32 & 0xFFFF)
		csum += uint32(ip >> 16 & 0xFFFF)
		csum += uint32(ip >> 0 & 0xFFFF)

		return
	}
	return
}
