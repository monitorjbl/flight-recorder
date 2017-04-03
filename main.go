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
	"strings"
	"strconv"
	"regexp"
)

var (
	device              string             = "en0"
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

func httpStartLine(line *string) HttpEvent {
	if strings.HasSuffix(*line, "HTTP/1.1") {
		matches := clientRequestRegex.FindAllString(*line, -1)
		return ClientRequestEvent{
			Method: matches[1],
			Path:   matches[2],
			Version:matches[3]}
	} else if strings.HasPrefix(*line, "HTTP/1.1") {
		matches := serverResponseRegex.FindAllString(*line, -1)
		return ServerResponseEvent{
			Status: matches[2],
			Version:matches[1]}
	} else {
		return nil
	}
}

func contentLength(line *string) int {
	if strings.HasPrefix(*line, "Content-Length: ") {
		split := strings.Split(*line, ": ")
		l, _ := strconv.Atoi(strings.TrimSpace(split[1]))
		return l
	} else {
		return -1
	}
}

func transmogrify(streamId string) {
	dir := fmt.Sprintf("%s/%s/%s", storage_dir, inflight_dir, streamId)
	defer func() {
		log.Debugf("Removing inflight dir for stream %v", streamId)
		os.RemoveAll(dir)
	}()

	reader, err := NewStreamReader(streamId)
	if err != nil {
		log.Errorf("Could not process stream %v", streamId)
		return
	}

	//Go byte-by-byte through the files content and look for <CR><LF> combinations.
	events := []HttpEvent{}
	var currentEvent HttpEvent = nil
	scanningEvent := false
	buffer := make([]byte, 1024)
	window := [2]byte{}
	start := 0
	for {
		bytesRead, err := reader.Read(buffer)
		if err != nil {
			log.Errorf("Error reading packet data: %v", err)
			return
		}

		for i := uint64(0); i < bytesRead-1; i++ {
			window[0] = buffer[i]
			window[1] = buffer[i + 1]
			if window == crlf {
				line := string(buffer[start:i - 1])
				if hsl := httpStartLine(&line); !scanningEvent && hsl != nil {
					currentEvent = hsl
					scanningEvent = true
				} else if cl := contentLength(&line); scanningEvent && cl >= 0 {
					//if this is a client upload, save the data. else, discard it
					reader.Skip(uint64(cl))
					break
				}
			}
		}
		events = append(events, currentEvent)
	}

}

func dumpPayload(streamId *string, seqId *uint32, data *[]byte) {
	dir := fmt.Sprintf("%s/%s/%s", storage_dir, inflight_dir, streamId)
	if !inflight.Has(dir) {
		os.MkdirAll(dir, 0755)
		inflight.SetIfAbsent(*streamId, time.Now())
	}
	ioutil.WriteFile(fmt.Sprintf("%s/%s", dir, seqId), *data, 0644)
}

func handlePacket(ip *layers.IPv4, tcp *layers.TCP) {
	defer atomic.AddInt64(&threadcount, -1)
	streamId := fmt.Sprintf("%v_%d-%v_%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

	if tcp.FIN {
		fmt.Printf("CLOSE  %v: %d\n", streamId, tcp.Seq)
		inflight.Remove(streamId)
		go transmogrify(streamId)
	} else {
		fmt.Printf("WRITE %v/%d\n", streamId, tcp.Seq)
		dumpPayload(&streamId, &tcp.Seq, &tcp.Payload)
	}
}

func main() {
	inflight = cmap.New()

	// Open device
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	skipTraffic := false
	skipMark := int64(0)
	for packet := range packetSource.Packets() {
		if skipTraffic {
			if time.Now().Unix() >= (skipMark + sleeptime) {
				skipTraffic = false
				log.Infof("Resuming traffic inspection")
			} else {
				continue
			}
		}

		// Get source IP
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if threadcount < threadcap {
				atomic.AddInt64(&threadcount, 1)
				go handlePacket(ip, tcp)
			} else {
				log.Warnf("Reached threadlimit of %v, ignoring traffic for %v seconds", threadcap, sleeptime)
				skipMark = time.Now().Unix()
				skipTraffic = true
			}
		}
	}
}
