package tcpip

func (self Packet) IHL() int {
	return int(self.Raw[0]&0xF) * 4
}

func (self Packet) DSCP() int {
	return int(self.Raw[1] >> 2)
}

func (self Packet) ECN() int {
	return int(self.Raw[1] & 0x3)
}

func (self Packet) TotalLength() int {
	return int(self.Raw[2])<<8 | int(self.Raw[3])
}

func (self Packet) SetTotalLength(length int) {
	self.Raw[2] = byte(length >> 8)
	self.Raw[3] = byte(length)
}

func (self Packet) Identification() int {
	return int(self.Raw[4])<<8 | int(self.Raw[5])
}

func (self Packet) Flags() int {
	return int(self.Raw[6] >> 5)
}

func (self Packet) FragmentOffset() int {
	return int(self.Raw[6]&0x1F)<<8 | int(self.Raw[7])
}

func (self Packet) TimeToLive() int {
	return int(self.Raw[8])
}

func (self Packet) Protocol() IPPROTOCOL {
	return IPPROTOCOL(self.Raw[9])
}

func (self Packet) HeaderChecksum() int {
	return int(self.Raw[10])<<8 | int(self.Raw[11])
}

func (self Packet) SetHeaderChecksum(sum int) {
	self.Raw[10] = byte(sum >> 8)
	self.Raw[11] = byte(sum >> 0)
}

func (self Packet) SourceIPAddress() uint32 {
	return uint32(self.Raw[12])<<24 | uint32(self.Raw[13])<<16 | uint32(self.Raw[14])<<8 | uint32(self.Raw[15])
}

func (self Packet) SetSourceIPAddress(ip uint32) {
	self.Raw[12] = byte(ip >> 24)
	self.Raw[13] = byte(ip >> 16)
	self.Raw[14] = byte(ip >> 8)
	self.Raw[15] = byte(ip >> 0)
}

func (self Packet) DestinationIPAddress() uint32 {
	return uint32(self.Raw[16])<<24 | uint32(self.Raw[17])<<16 | uint32(self.Raw[18])<<8 | uint32(self.Raw[19])
}

func (self Packet) SetDestinationIPAddress(ip uint32) {
	self.Raw[16] = byte(ip >> 24)
	self.Raw[17] = byte(ip >> 16)
	self.Raw[18] = byte(ip >> 8)
	self.Raw[19] = byte(ip >> 0)
}

func (self Packet) Options() []byte {
	return self.Raw[20:self.IHL()]
}
