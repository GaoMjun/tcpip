package tcpip

func (self Packet) IHL() int {
	return int(self.Raw[self.Offset+0]&0xF) * 4
}

func (self Packet) DSCP() int {
	return int(self.Raw[self.Offset+1] >> 2)
}

func (self Packet) ECN() int {
	return int(self.Raw[self.Offset+1] & 0x3)
}

func (self Packet) TotalLength() int {
	return int(self.Raw[self.Offset+2])<<8 | int(self.Raw[self.Offset+3])
}

func (self Packet) SetTotalLength(length int) {
	self.Raw[self.Offset+2] = byte(length >> 8)
	self.Raw[self.Offset+3] = byte(length)
}

func (self Packet) Identification() int {
	return int(self.Raw[self.Offset+4])<<8 | int(self.Raw[self.Offset+5])
}

func (self Packet) Flags() int {
	return int(self.Raw[self.Offset+6] >> 5)
}

func (self Packet) FragmentOffset() int {
	return int(self.Raw[self.Offset+6]&0x1F)<<8 | int(self.Raw[self.Offset+7])
}

func (self Packet) TimeToLive() int {
	return int(self.Raw[self.Offset+8])
}

func (self Packet) Protocol() IPPROTOCOL {
	return IPPROTOCOL(self.Raw[self.Offset+9])
}

func (self Packet) HeaderChecksum() int {
	return int(self.Raw[self.Offset+10])<<8 | int(self.Raw[self.Offset+11])
}

func (self Packet) SetHeaderChecksum(sum int) {
	self.Raw[self.Offset+10] = byte(sum >> 8)
	self.Raw[self.Offset+11] = byte(sum >> 0)
}

func (self Packet) SourceIPAddress() uint32 {
	return uint32(self.Raw[self.Offset+12])<<24 |
		uint32(self.Raw[self.Offset+13])<<16 |
		uint32(self.Raw[self.Offset+14])<<8 |
		uint32(self.Raw[self.Offset+15])
}

func (self Packet) SetSourceIPAddress(ip uint32) {
	self.Raw[self.Offset+12] = byte(ip >> 24)
	self.Raw[self.Offset+13] = byte(ip >> 16)
	self.Raw[self.Offset+14] = byte(ip >> 8)
	self.Raw[self.Offset+15] = byte(ip >> 0)
}

func (self Packet) DestinationIPAddress() uint32 {
	return uint32(self.Raw[self.Offset+16])<<24 |
		uint32(self.Raw[self.Offset+17])<<16 |
		uint32(self.Raw[self.Offset+18])<<8 |
		uint32(self.Raw[self.Offset+19])
}

func (self Packet) SetDestinationIPAddress(ip uint32) {
	self.Raw[self.Offset+16] = byte(ip >> 24)
	self.Raw[self.Offset+17] = byte(ip >> 16)
	self.Raw[self.Offset+18] = byte(ip >> 8)
	self.Raw[self.Offset+19] = byte(ip >> 0)
}

func (self Packet) Options() []byte {
	return self.Raw[self.Offset+20 : self.IHL()]
}
