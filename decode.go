package pcap

import (
	"fmt"
	"bufio"
	"os"
	"time"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD
	IP_ICMP  = 1
	IP_INIP  = 4
	IP_TCP   = 6
	IP_UDP   = 17
)

var out *bufio.Writer
var errout *bufio.Writer

func init() {
    out = bufio.NewWriter(os.Stdout)
    errout = bufio.NewWriter(os.Stderr)
}

func DecodeEthernetPkt(pkt *Packet) (packet *DecodedPkt) {

	packet = new(DecodedPkt)

	packet.PcapPktHdr = pkt
	packet.EthernetHeader = DecodeEther(pkt.Data)

	switch packet.EthernetHeader.Type {
	case TYPE_IP:
		packet.IpHeader, packet.UdpHeader, packet.TcpHeader, packet.IcmpHeader = Decodeip(pkt.Data[14:])
	case TYPE_ARP:
		packet.ArpHeader = Decodearp(pkt.Data[14:])
		// 	case TYPE_IP6:
		// 		Decodeip6(pkt.Data[14:])
// 	default:
// 		Unsupported(packet.EthernetHeader.Type)
	}

	return
}

type DecodedPkt struct {
	PcapPktHdr     *Packet
	EthernetHeader *EtherHdr
	ArpHeader      *Arphdr
	IpHeader       *Iphdr
	TcpHeader      *Tcphdr
	UdpHeader      *Udphdr
	IcmpHeader     *Icmphdr
	Data           []byte
}

type EtherHdr struct {
	DestMacAddress uint64
	SrcMacAddress  uint64
	Type           uint16
	Data           []byte
}


func DecodeEther(pkt []byte) (hdr *EtherHdr) {

	hdr = new(EtherHdr)

	hdr.DestMacAddress = Decodemac(pkt[0:6])
	hdr.SrcMacAddress = Decodemac(pkt[6:12])
	hdr.Type = Decodeuint16(pkt[12:14])
	hdr.Data = pkt[14:]

	return
}

func Decodemac(pkt []byte) uint64 {
	mac := uint64(0)
	for i := uint(0); i < 6; i++ {
		mac = (mac << 8) + uint64(pkt[i])
	}
	return mac
}

func Decodeuint16(pkt []byte) uint16 {
	return uint16(pkt[0])<<8 + uint16(pkt[1])
}

func Decodeuint32(pkt []byte) uint32 {
	return uint32(pkt[0])<<24 + uint32(pkt[1])<<16 + uint32(pkt[2])<<8 + uint32(pkt[3])
}

func Unsupported(pkttype uint16) {
	fmt.Printf("unsupported protocol %d\n", int(pkttype))
}

type Arphdr struct {
	Addrtype          uint16
	Protocol          uint16
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DestHwAddress     []byte
	DestProtAddress   []byte
	Data    []byte
}

func Decodearp(pkt []byte) (arp *Arphdr) {
	arp = new(Arphdr)
	arp.Addrtype = Decodeuint16(pkt[0:2])
	arp.Protocol = Decodeuint16(pkt[2:4])
	arp.HwAddressSize = pkt[4]
	arp.ProtAddressSize = pkt[5]
	arp.Operation = Decodeuint16(pkt[6:8])
	arp.SourceHwAddress = pkt[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = pkt[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestHwAddress = pkt[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestProtAddress = pkt[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]
    arp.Data = pkt[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
	return
}

type Iphdr struct {
	Version    uint8
	Ihl        uint8
	Tos        uint8
	Length     uint16
	Id         uint16
	Flags      uint8
	FragOffset uint16
	Ttl        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIp      []byte
	DestIp     []byte
}

type INIPHdr struct {
	Iphdr
}

func Decodeip(pkt []byte) (ip *Iphdr, udphdr *Udphdr, tcphdr *Tcphdr, icmphdr *Icmphdr) {
	ip = new(Iphdr)
	udphdr = new(Udphdr)
	tcphdr = new(Tcphdr)
	icmphdr = new(Icmphdr)

	ip.Version = uint8(pkt[0]) >> 4
	ip.Ihl = uint8(pkt[0]) & 0x0F
	ip.Tos = pkt[1]
	ip.Length = Decodeuint16(pkt[2:4])
	ip.Id = Decodeuint16(pkt[4:6])
	flagsfrags := Decodeuint16(pkt[6:8])
	ip.Flags = uint8(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.Ttl = pkt[8]
	ip.Protocol = pkt[9]
	ip.Checksum = Decodeuint16(pkt[10:12])
	ip.SrcIp = pkt[12:16]
	ip.DestIp = pkt[16:20]
	

	switch ip.Protocol {
	case IP_TCP:
		tcphdr = Decodetcp(ip, pkt[ip.Ihl*4:])
		udphdr = nil
        icmphdr = nil
	case IP_UDP:
		udphdr = Decodeudp(ip, pkt[ip.Ihl*4:])
		tcphdr = nil
        icmphdr = nil
	case IP_ICMP:
		icmphdr = Decodeicmp(ip, pkt[ip.Ihl*4:])
		tcphdr = nil
        udphdr = nil
	case IP_INIP:
		_, _, _, _ = Decodeip(pkt[ip.Ihl*4:])
	default:
		fmt.Printf(" unsupported protocol %d", int(ip.Protocol))
	}

	return
}

type Tcphdr struct {
	SrcPort    uint16
	DestPort   uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Data       []byte
}

const (
	TCP_FIN = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
)

func Decodetcp(ip *Iphdr, pkt []byte) (tcp *Tcphdr) {
	tcp = new(Tcphdr)
	tcp.SrcPort = Decodeuint16(pkt[0:2])
	tcp.DestPort = Decodeuint16(pkt[2:4])
	tcp.Seq = Decodeuint32(pkt[4:8])
	tcp.Ack = Decodeuint32(pkt[8:12])
	tcp.DataOffset = pkt[12] & 0x0F
	tcp.Flags = uint8(Decodeuint16(pkt[12:14]) & 0x3F)
	tcp.Window = Decodeuint16(pkt[14:16])
	tcp.Checksum = Decodeuint16(pkt[16:18])
	tcp.Urgent = Decodeuint16(pkt[18:20])
	tcp.Data = pkt[tcp.DataOffset*4:]

	return
}

type Udphdr struct {
	SrcPort  uint16
	DestPort uint16
	Length   uint16
	Checksum uint16
	Data    []byte
}

func Decodeudp(ip *Iphdr, pkt []byte) (udp *Udphdr) {
	udp = new(Udphdr)

	udp.SrcPort = Decodeuint16(pkt[0:2])
	udp.DestPort = Decodeuint16(pkt[2:4])
	udp.Length = Decodeuint16(pkt[4:6])
	udp.Checksum = Decodeuint16(pkt[6:8])
	udp.Data = pkt[8:]
	return
}

type Icmphdr struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Id       uint16
	Seq      uint16
	Data     []byte
}

func Decodeicmp(ip *Iphdr, pkt []byte) (icmp *Icmphdr) {
	icmp = new(Icmphdr)
	icmp.Type = pkt[0]
	icmp.Code = pkt[1]
	icmp.Checksum = Decodeuint16(pkt[2:4])
	icmp.Id = Decodeuint16(pkt[4:6])
	icmp.Seq = Decodeuint16(pkt[6:8])
	icmp.Data = pkt[8:]
	return
}

func PrintDecodedPkt(packet *DecodedPkt) {
    t := time.SecondsToLocalTime(int64(packet.PcapPktHdr.Time.Sec))
    fmt.Fprintf(out, "%02d:%02d:%02d.%06d ", t.Hour, t.Minute, t.Second, packet.PcapPktHdr.Time.Usec)   
    switch {
    case packet.ArpHeader != nil:
        Printarp(packet.ArpHeader)
    case packet.IpHeader != nil:
        switch {
        case packet.TcpHeader != nil:
            Printtcp(packet.IpHeader, packet.TcpHeader)
        case packet.UdpHeader != nil:
            Printudp(packet.IpHeader, packet.UdpHeader)
        case packet.IcmpHeader != nil:
            Printicmp(packet.IpHeader, packet.IcmpHeader)
        }
    }
    out.WriteString("\n")
    out.Flush()
}

func Arpop(op uint16) string {
    switch op {
    case 1:
        return "Request"
    case 2:
        return "Reply"
    }
    return ""
}

func Printarp(arp *Arphdr) {
    fmt.Fprintf(out, "ARP, %s ", Arpop(arp.Operation))

    if arp.Addrtype == LINKTYPE_ETHERNET && arp.Protocol == TYPE_IP {
        fmt.Fprintf(out, "%012x (", Decodemac(arp.SourceHwAddress))
        Printip(arp.SourceProtAddress)
        fmt.Fprintf(out, ") > %012x (", Decodemac(arp.DestHwAddress))
        Printip(arp.DestProtAddress)
        fmt.Fprintf(out, ")")
    } else {
        fmt.Fprintf(out, "addrtype = %d protocol = %d", arp.Addrtype, arp.Protocol)
    }
}


func Printflags(flags uint8) {
    out.WriteString("[ ")
    if 0 != (flags & TCP_SYN) {
        out.WriteString("syn ")
    }
    if 0 != (flags & TCP_FIN) {
        out.WriteString("fin ")
    }
    if 0 != (flags & TCP_ACK) {
        out.WriteString("ack ")
    }
    if 0 != (flags & TCP_PSH) {
        out.WriteString("psh ")
    }
    if 0 != (flags & TCP_RST) {
        out.WriteString("rst ")
    }
    if 0 != (flags & TCP_URG) {
        out.WriteString("urg ")
    }
    out.WriteString("]")
}


func Printip(ip []byte) {
    for i := 0; i < 4; i++ {
        fmt.Fprintf(out, "%d", int(ip[i]))
        if i < 3 {
            out.WriteString(".")
        }
    }
}

func Printtcp(ip *Iphdr, tcp *Tcphdr) {
    out.WriteString("TCP, ")
    Printip(ip.SrcIp)
    fmt.Fprintf(out, ":%d > ", int(tcp.SrcPort))
    Printip(ip.DestIp)
    fmt.Fprintf(out, ":%d ", int(tcp.DestPort))
    Printflags(tcp.Flags)
    fmt.Fprintf(out, " SEQ=%d ACK=%d WIN=%d LEN=%d", 
                int64(tcp.Seq), int64(tcp.Ack),int64(tcp.Window),int64(len(tcp.Data)))
}

func Printudp(ip *Iphdr, udp *Udphdr) {
    out.WriteString("UDP, ")
    Printip(ip.SrcIp)
    fmt.Fprintf(out, ":%d > ", udp.SrcPort)
    Printip(ip.DestIp)
    fmt.Fprintf(out, ":%d LEN=%d CHKSUM=%d", int(udp.DestPort), int(udp.Length), int(udp.Checksum))
}

func Printicmp(ip *Iphdr, icmp *Icmphdr) {
    out.WriteString("ICMP, ")
    Printip(ip.SrcIp)
    out.WriteString(" > ")
    Printip(ip.DestIp)
    fmt.Fprintf(out, " Type = %d Code = %d ", icmp.Type, icmp.Code)
    switch icmp.Type {
    case 0:
        fmt.Fprintf(out, "Echo reply ttl=%d seq=%d len=%d", ip.Ttl, icmp.Seq,len(icmp.Data))
    case 3:
        switch icmp.Code {
        case 0:
            out.WriteString("Network unreachable")
        case 1:
            out.WriteString("Host unreachable")
        case 2:
            out.WriteString("Protocol unreachable")
        case 3:
            out.WriteString("Port unreachable")
        default:
            out.WriteString("Destination unreachable")
        }
    case 8:
        fmt.Fprintf(out, "Echo request ttl=%d seq=%d", ip.Ttl, icmp.Seq)
    case 30:
        out.WriteString("Traceroute")
    }
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func Hexdump(pkt *Packet) {
    for i := 0; i < len(pkt.Data); i += 16 {
        Dumpline(uint32(i), pkt.Data[i:min(i+16, len(pkt.Data))])
    }
}

func Dumpline(addr uint32, line []byte) {
    fmt.Fprintf(out, "\t0x%04x: ", int32(addr))
    var i uint16
    for i = 0; i < 16 && i < uint16(len(line)); i++ {
        if i%2 == 0 {
            out.WriteString(" ")
        }
        fmt.Fprintf(out, "%02x", line[i])
    }
    for j := i; j <= 16; j++ {
        if j%2 == 0 {
            out.WriteString(" ")
        }
        out.WriteString("  ")
    }
    out.WriteString("  ")
    for i = 0; i < 16 && i < uint16(len(line)); i++ {
        if line[i] >= 32 && line[i] <= 126 {
            fmt.Fprintf(out, "%c", line[i])
        } else {
            out.WriteString(".")
        }
    }
    out.WriteString("\n")
}

func Decodeip6(pkt []byte) {
    out.WriteString("TODO: IPv6")
}
