package types

type MyPacket struct {
	Proto    string
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Contents []byte
}
