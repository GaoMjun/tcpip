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

func (self Packet) SourceAddress() (b [16]byte) {
	copy(b[:], self.Raw[8:24])
	return
}

func (self Packet) DestinationAddress() (b [16]byte) {
	copy(b[:], self.Raw[24:40])
	return
}
