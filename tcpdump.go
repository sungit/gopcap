package main

import (
	"pcap"
	"fmt"
	"os"
	"flag"
)

var device *string
var snaplen *int
var hexdump *bool
var expr    string
var offlinefn   *string
var writefile   *string

func init(){
    device = flag.String("i", "eth0", "interface")
    snaplen = flag.Int("s", 65535, "snaplen")
    hexdump = flag.Bool("X", false, "hexdump")
    offlinefn = flag.String("r", "", "the tcpdump file to open")
    writefile = flag.String("w", "", "the tcpdump filename to write")

    flag.Usage = func() {
        fmt.Printf("usage: %s [ -i interface ] [ -f dumpfile ] [ -s snaplen ] [ -X ] [ expression ]\n", os.Args[0])
        flag.PrintDefaults()
    }

    flag.Parse()

    if (len(flag.Args()) > 0) {
        expr = flag.Arg(0)
    }
}

func main() {
    var h *pcap.Pcap
    var err string
    var dumper *pcap.PcapDumper
    
    if *offlinefn == "" {
        h, err = pcap.Openlive(*device, 1500, true, 0)
    }else{
        h, err = pcap.Openoffline(*offlinefn)
    }
    
    if *writefile != "" {
        dumper = pcap.NewPcapDumper(h,*writefile)
    }
    
	if h == nil {
		fmt.Printf("Warning: no devices found : %s\n", err)
		os.Exit(-1)
	}
	
	h.Setfilter(expr)

	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		packet := pcap.DecodeEthernetPkt(pkt)
        if dumper==nil {
            pcap.PrintDecodedPkt(packet)
        }else{
            dumper.Dump(packet.PcapPktHdr)
        }
	}
}
