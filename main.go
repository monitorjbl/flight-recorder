package main

import (
	"fmt"
	"time"
	"os"
	"sync/atomic"
	log "github.com/Sirupsen/logrus"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/orcaman/concurrent-map"
	"io/ioutil"
	"regexp"
)

var (
	device              string             = "enp7s0"
	storage_dir         string             = "/tmp/testing"
	inflight_dir        string             = "inflight"
	recorded_dir        string             = "record"
	dst_port            int32              = 80
	snapshot_len        int32              = 65535
	promiscuous         bool               = false
	timeout             time.Duration      = -1 * time.Second
	threadcount         int64              = 0
	threadcap           int64              = 1000
	sleeptime           int64              = 3
	inflight            cmap.ConcurrentMap = nil
	crlf                [2]byte            = [2]byte{0x0D, 0x0A}
	clientRequestRegex  *regexp.Regexp     = regexp.MustCompile("([^\\s]+) ([^\\s]+) ([^\\s]+)")
	serverResponseRegex *regexp.Regexp     = regexp.MustCompile("([^\\s]+) (.+)")
)

type HttpEvent interface {
}

type ClientRequestEvent struct {
	HttpEvent
	Method  string
	Path    string
	Version string
}

type ServerResponseEvent struct {
	HttpEvent
	Status  string
	Version string
}

func dumpPayload(streamId *string, seqId *uint32, data *[]byte) {
	dir := fmt.Sprintf("%s/%s/%s", storage_dir, inflight_dir, *streamId)
	if !inflight.Has(dir) {
		os.MkdirAll(dir, 0755)
		inflight.SetIfAbsent(*streamId, time.Now())
	}

	if data != nil && len(*data) > 0 {
		file := fmt.Sprintf("%s/%v", dir, *seqId)
		log.Infof("Writing %v bytes to ", file)
		ioutil.WriteFile(file, *data, 0644)
	} else {
		log.Debugf("Skipping empty payload for %v: %v", dir, *data)
	}
}

func handlePacket(ip *layers.IPv4, tcp *layers.TCP) {
	defer atomic.AddInt64(&threadcount, -1)
	streamId := fmt.Sprintf("%v_%d-%v_%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

	if tcp.FIN {
		log.Infof("Connection from %v to %v is closed", ip.SrcIP, ip.DstIP)
		inflight.Remove(streamId)
		transmogrify(streamId)
	} else {
		log.Debugf("Dumping packet from %v", ip.SrcIP)
		dumpPayload(&streamId, &tcp.Seq, &tcp.Payload)
	}
}

func main() {
	log.SetLevel(log.DebugLevel)
	inflight = cmap.New()

	// Open device
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatalf("Could not set tcp filter")
		return
	}

	// Use the handle as a packet source to process all packets
	//skipTraffic := false
	//skipMark := int64(0)

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	decoded := []gopacket.LayerType{}
	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatalf("Could not get packet: %v", err)
			break
		}

		err = parser.DecodeLayers(data, &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeTCP:
				handlePacket(&ip4, &tcp)
			}
		}
	}


	//
	//// Use the handle as a packet source to process all packets
	//packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//skipTraffic := false
	//skipMark := int64(0)
	//for packet := range packetSource.Packets() {
	//	if skipTraffic {
	//		if time.Now().Unix() >= (skipMark + sleeptime) {
	//			skipTraffic = false
	//			log.Infof("Resuming traffic inspection")
	//		} else {
	//			continue
	//		}
	//	}
	//
	//	// Get source IP
	//	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	//	if ipLayer == nil {
	//		continue
	//	}
	//	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	//
	//	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	//		tcp, _ := tcpLayer.(*layers.TCP)
	//		if threadcount < threadcap {
	//			atomic.AddInt64(&threadcount, 1)
	//			handlePacket(ip, tcp)
	//		} else {
	//			log.Warnf("Reached threadlimit of %v, ignoring traffic for %v seconds", threadcap, sleeptime)
	//			skipMark = time.Now().Unix()
	//			skipTraffic = true
	//		}
	//	}
	//}
}
