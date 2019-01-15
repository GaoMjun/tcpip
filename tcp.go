package tcpip

func (self Packet) SourcePort() int {
	offset := self.IHL()
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) SetSourcePort(port int) {
	offset := self.IHL()
	self.Raw[offset] = byte(port >> 8)
	self.Raw[offset+1] = byte(port >> 0)
}

func (self Packet) DestinationPort() int {
	offset := self.IHL() + 2
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) SetDestinationPort(port int) {
	offset := self.IHL() + 2
	self.Raw[offset] = byte(port >> 8)
	self.Raw[offset+1] = byte(port >> 0)
}

func (self Packet) SequenceNumber() int {
	offset := self.IHL() + 2 + 2
	return int(self.Raw[offset])<<24 | int(self.Raw[offset+1])<<16 | int(self.Raw[offset+2])<<8 | int(self.Raw[offset+3])
}

func (self Packet) AcknowledgmentNumber() int {
	offset := self.IHL() + 2 + 2 + 4
	return int(self.Raw[offset])<<24 | int(self.Raw[offset+1])<<16 | int(self.Raw[offset+2])<<8 | int(self.Raw[offset+3])
}

func (self Packet) DataOffset() int {
	offset := self.IHL() + 2 + 2 + 4 + 4
	return (int(self.Raw[offset]&0xF0) >> 4) * 4
}

func (self Packet) Reserved() int {
	offset := self.IHL() + 2 + 2 + 4 + 4
	return int(self.Raw[offset]&0xE) >> 1
}

func (self Packet) NS() int {
	offset := self.IHL() + 2 + 2 + 4 + 4
	return int(self.Raw[offset] & 0x1)
}

func (self Packet) CWR() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x80) >> 7
}

func (self Packet) ECE() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x40) >> 6
}

func (self Packet) URG() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x20) >> 5
}

func (self Packet) ACK() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x10) >> 4
}

func (self Packet) PSH() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x8) >> 3
}

func (self Packet) RST() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x4) >> 2
}

func (self Packet) SYN() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset]&0x2) >> 1
}

func (self Packet) FIN() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1
	return int(self.Raw[offset] & 0x1)
}

func (self Packet) WindowSize() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1 + 1
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) TCPChecksum() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1 + 1 + 2
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) SetTCPChecksum(sum int) {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1 + 1 + 2
	self.Raw[offset] = byte(sum >> 8)
	self.Raw[offset+1] = byte(sum >> 0)
}

func (self Packet) UrgentPointer() int {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1 + 1 + 2 + 2
	return int(self.Raw[offset])<<8 | int(self.Raw[offset+1])
}

func (self Packet) TCPOptions() []byte {
	offset := self.IHL() + 2 + 2 + 4 + 4 + 1 + 1 + 2 + 2 + 2
	return self.Raw[offset : self.IHL()+self.DataOffset()]
}
