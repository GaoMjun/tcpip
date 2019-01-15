package tcpip

func (self Packet) TrafficClass() int {
	return int(self.Raw[0]&0xF)<<4 | int(self.Raw[1]&0xF0)>>4
}

func (self Packet) FlowLabel() int {
	return int(self.Raw[1]&0xF)<<16 | int(self.Raw[2])<<8 | int(self.Raw[3])
}

func (self Packet) PayloadLength() int {
	return int(self.Raw[4])<<8 | int(self.Raw[5])
}

func (self Packet) NextHeader() IPPROTOCOL {
	return IPPROTOCOL(self.Raw[6])
}

func (self Packet) HopLimit() int {
	return int(self.Raw[7])
}

func (self Packet) SourceAddress() uint64 {
	return uint64(self.Raw[8])<<56 | uint64(self.Raw[9])<<48 | uint64(self.Raw[10])<<40 | uint64(self.Raw[11])<<32 |
		uint64(self.Raw[12])<<24 | uint64(self.Raw[13])<<16 | uint64(self.Raw[14])<<8 | uint64(self.Raw[15])
}

func (self Packet) DestinationAddress() uint64 {
	return uint64(self.Raw[16])<<56 | uint64(self.Raw[17])<<48 | uint64(self.Raw[18])<<40 | uint64(self.Raw[19])<<32 |
		uint64(self.Raw[20])<<24 | uint64(self.Raw[21])<<16 | uint64(self.Raw[22])<<8 | uint64(self.Raw[23])
}
