package tcpip

func (self Packet) Type() int {
	offset := self.Offset + self.IHL()
	return int(self.Raw[offset])
}

func (self Packet) SetType(t int) {
	offset := self.Offset + self.IHL()
	self.Raw[offset] = byte(t)
	return
}

func (self Packet) Code() int {
	offset := self.Offset + self.IHL() + 1
	return int(self.Raw[offset])
}

func (self Packet) ICMPChecksum() int {
	offset := self.Offset + self.IHL() + 1 + 1
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) SetICMPChecksum(sum int) {
	offset := self.Offset + self.IHL() + 1 + 1
	self.Raw[offset] = byte(sum >> 8)
	self.Raw[offset+1] = byte(sum >> 0)
}

func (self Packet) RestOfHeader() []byte {
	offset := self.Offset + self.IHL() + 1 + 1 + 2
	return self.Raw[offset : offset+4]
}
