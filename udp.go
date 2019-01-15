package tcpip

func (self Packet) Length() int {
	offset := self.IHL() + 2 + 2
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) UDPChecksum() int {
	offset := self.IHL() + 2 + 2 + 2
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) SetUDPChecksum(sum int) {
	offset := self.IHL() + 2 + 2 + 2
	self.Raw[offset] = byte(sum >> 8)
	self.Raw[offset+1] = byte(sum)
}