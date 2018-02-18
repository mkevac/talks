package main

import (
	"flag"
	"log"
	"time"

	"bufio"

	"encoding/binary"

	"io"

	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const (
	snapshotLen = 1024
	promiscuous = false
	timeout     = time.Second * 30
)

var config struct {
	device string
	file   string
	filter string
	port   uint
}

type key struct {
	net, transport gopacket.Flow
}

func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

type bidi struct {
	key            key         // Key of the first stream, mostly for logging.
	a, b           *gpbsStream // the two bidirectional streams.
	lastPacketSeen time.Time   // last time we saw a packet from either stream.
}

// httpStreamFactory implements tcpassembly.StreamFactory
type gpbsStreamFactory struct {
	bidiMap map[key]*bidi
	port    uint
}

func (gsf *gpbsStreamFactory) New(net gopacket.Flow, transport gopacket.Flow) tcpassembly.Stream {
	gstream := &gpbsStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}

	k := key{net, transport}
	bd := gsf.bidiMap[k]
	if bd == nil {
		bd = &bidi{a: gstream, key: k}
		log.Printf("[%v] created first side of bidirectional stream", bd.key)
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		gsf.bidiMap[key{net.Reverse(), transport.Reverse()}] = bd
	} else {
		log.Printf("[%v] found second side of bidirectional stream", bd.key)
		bd.b = gstream
		// Clear out the bidi we're using from the map, just in case.
		delete(gsf.bidiMap, k)
	}
	gstream.bidi = bd

	var port uint
	dst := transport.Dst()
	if dst.EndpointType() == layers.EndpointTCPPort {
		port = uint(binary.BigEndian.Uint16(dst.Raw()))
	} else {
		panic("wrong dst")
	}

	if port == gsf.port {
		// this is request
		gstream.requests = true
	}

	go gstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &gstream.r
}

// gpbsStream will handle the actual decoding of gpbs requests.
type gpbsStream struct {
	net       gopacket.Flow
	transport gopacket.Flow
	r         tcpreader.ReaderStream
	bidi      *bidi
	requests  bool
}

func (g *gpbsStream) run() {

	var (
		msgLenBuf [4]byte
		msgIDBuf  [4]byte
	)

	buf := bufio.NewReader(&g.r)

	for {

		n, err := buf.Read(msgLenBuf[:])
		if err != nil {
			if err == io.EOF {
				return
			}

			log.Printf("error while reading msgLen: %s", err)
			return
		}

		if n != 4 {
			log.Printf("unexpected read size (expected 4, got %v)", n)
			return
		}

		n, err = buf.Read(msgIDBuf[:])
		if err != nil {
			log.Printf("error while reading msgLen: %s", err)
			return
		}

		if n != 4 {
			log.Printf("unexpected read size (expected 4, got %v)", n)
			return
		}

		msgLen := binary.BigEndian.Uint32(msgLenBuf[:])
		msgID := binary.BigEndian.Uint32(msgIDBuf[:])

		if g.requests {
			log.Printf("read request msgid %v", msgID)
		} else {
			log.Printf("read response msgid %v", msgID)
		}

		msgData := make([]byte, msgLen-4)

		n, err = buf.Read(msgData)
		if err != nil {
			log.Printf("error while reading msgLen: %s", err)
			return
		}

		if n != (int(msgLen) - 4) {
			log.Printf("unexpected read size (expected %v, got %v)", msgLen-4, n)
			return
		}
	}
}

func main() {
	var err error

	flag.StringVar(&config.device, "device", "eth0", "network device to use")
	flag.StringVar(&config.file, "file", "", "pcap file to read from")
	flag.StringVar(&config.filter, "filter", "tcp and port 11050", "BPF filter for pcap")
	flag.UintVar(&config.port, "port", 11050, "port service is listening on")

	flag.Parse()

	var handle *pcap.Handle

	if config.file != "" {
		handle, err = pcap.OpenOffline(config.file)
	} else {
		handle, err = pcap.OpenLive(config.device, snapshotLen, promiscuous, timeout)
	}

	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(config.filter); err != nil {
		log.Fatal(err)
	}

	streamFactory := &gpbsStreamFactory{
		bidiMap: make(map[key]*bidi),
		port:    config.port,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := packetSource.Packets()

	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:

			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}

			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
