package engine

import (
	"context"
	"time"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/ruleset"

	"github.com/bwmarrin/snowflake"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

const (
	defaultChanSize                         = 64
	defaultTCPMaxBufferedPagesTotal         = 65536
	defaultTCPMaxBufferedPagesPerConnection = 16
	defaultTCPTimeout                       = 10 * time.Minute
	defaultUDPMaxStreams                    = 4096

	tcpFlushInterval = 1 * time.Minute
)

type workerPacket struct {
	StreamID   uint32
	Packet     gopacket.Packet
	LinkType   layers.LinkType
	SetVerdict func(io.Verdict, []byte) error
}

type worker struct {
	id         int
	packetChan chan *workerPacket
	logger     Logger
	decap      *decapDecoder

	tcpStreamFactory *tcpStreamFactory
	tcpStreamPool    *reassembly.StreamPool
	tcpAssembler     *reassembly.Assembler
	tcpTimeout       time.Duration

	udpStreamFactory *udpStreamFactory
	udpStreamManager *udpStreamManager

	modSerializeBuffer gopacket.SerializeBuffer
}

type workerConfig struct {
	ID                         int
	ChanSize                   int
	Logger                     Logger
	Ruleset                    ruleset.Ruleset
	TCPMaxBufferedPagesTotal   int
	TCPMaxBufferedPagesPerConn int
	TCPTimeout                 time.Duration
	UDPMaxStreams              int
	Decap                      bool
	DecapMaxDepth              int
	DecapMaxInnerPacketSize    int
}

func (c *workerConfig) fillDefaults() {
	if c.ChanSize <= 0 {
		c.ChanSize = defaultChanSize
	}
	if c.TCPMaxBufferedPagesTotal <= 0 {
		c.TCPMaxBufferedPagesTotal = defaultTCPMaxBufferedPagesTotal
	}
	if c.TCPMaxBufferedPagesPerConn <= 0 {
		c.TCPMaxBufferedPagesPerConn = defaultTCPMaxBufferedPagesPerConnection
	}
	if c.TCPTimeout <= 0 {
		c.TCPTimeout = defaultTCPTimeout
	}
	if c.UDPMaxStreams <= 0 {
		c.UDPMaxStreams = defaultUDPMaxStreams
	}
	if c.DecapMaxDepth <= 0 {
		c.DecapMaxDepth = defaultDecapMaxDepth
	}
	if c.DecapMaxInnerPacketSize <= 0 {
		c.DecapMaxInnerPacketSize = defaultDecapMaxInnerPacketSize
	}
}

func newWorker(config workerConfig) (*worker, error) {
	config.fillDefaults()
	sfNode, err := snowflake.NewNode(int64(config.ID))
	if err != nil {
		return nil, err
	}
	tcpSF := &tcpStreamFactory{
		WorkerID: config.ID,
		Logger:   config.Logger,
		Node:     sfNode,
		Ruleset:  config.Ruleset,
	}
	tcpStreamPool := reassembly.NewStreamPool(tcpSF)
	tcpAssembler := reassembly.NewAssembler(tcpStreamPool)
	tcpAssembler.MaxBufferedPagesTotal = config.TCPMaxBufferedPagesTotal
	tcpAssembler.MaxBufferedPagesPerConnection = config.TCPMaxBufferedPagesPerConn
	udpSF := &udpStreamFactory{
		WorkerID: config.ID,
		Logger:   config.Logger,
		Node:     sfNode,
		Ruleset:  config.Ruleset,
	}
	udpSM, err := newUDPStreamManager(udpSF, config.UDPMaxStreams)
	if err != nil {
		return nil, err
	}
	decap := &decapDecoder{
		enabled:            config.Decap,
		maxDepth:           config.DecapMaxDepth,
		maxInnerPacketSize: config.DecapMaxInnerPacketSize,
	}
	return &worker{
		id:                 config.ID,
		packetChan:         make(chan *workerPacket, config.ChanSize),
		logger:             config.Logger,
		decap:              decap,
		tcpStreamFactory:   tcpSF,
		tcpStreamPool:      tcpStreamPool,
		tcpAssembler:       tcpAssembler,
		tcpTimeout:         config.TCPTimeout,
		udpStreamFactory:   udpSF,
		udpStreamManager:   udpSM,
		modSerializeBuffer: gopacket.NewSerializeBuffer(),
	}, nil
}

func (w *worker) Feed(p *workerPacket) {
	w.packetChan <- p
}

func (w *worker) Run(ctx context.Context) {
	w.logger.WorkerStart(w.id)
	defer w.logger.WorkerStop(w.id)

	tcpFlushTicker := time.NewTicker(tcpFlushInterval)
	defer tcpFlushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case wPkt := <-w.packetChan:
			if wPkt == nil {
				// Closed
				return
			}
			v, b := w.handle(wPkt.StreamID, wPkt.Packet, wPkt.LinkType)
			_ = wPkt.SetVerdict(v, b)
		case <-tcpFlushTicker.C:
			w.flushTCP(w.tcpTimeout)
		}
	}
}

func (w *worker) UpdateRuleset(r ruleset.Ruleset) error {
	if err := w.tcpStreamFactory.UpdateRuleset(r); err != nil {
		return err
	}
	return w.udpStreamFactory.UpdateRuleset(r)
}

func (w *worker) handle(streamID uint32, p gopacket.Packet, linkType layers.LinkType) (io.Verdict, []byte) {
	if w.decap.enabled {
		result, err := w.decap.Decode(p.Data(), linkType)
		if err == nil && result.Encap != nil {
			*result.Packet.Metadata() = *p.Metadata()
			v, b := w.handlePacket(streamID, result.Packet, result.Encap)
			// Verdicts apply to the outer packet, which may carry other streams
			switch v {
			case io.VerdictAcceptModify, io.VerdictAcceptStream:
				return io.VerdictAccept, nil
			case io.VerdictDropStream:
				return io.VerdictDrop, nil
			}
			return v, b
		}
	}
	return w.handlePacket(streamID, p, nil)
}

func (w *worker) handlePacket(streamID uint32, p gopacket.Packet, encap analyzer.PropMap) (io.Verdict, []byte) {
	netLayer, trLayer := p.NetworkLayer(), p.TransportLayer()
	if netLayer == nil || trLayer == nil {
		// Invalid packet
		return io.VerdictAccept, nil
	}
	ipFlow := netLayer.NetworkFlow()
	switch tr := trLayer.(type) {
	case *layers.TCP:
		return w.handleTCP(ipFlow, p.Metadata(), tr, encap), nil
	case *layers.UDP:
		if encap != nil {
			streamID = innerStreamID(streamID, ipFlow, tr.TransportFlow())
		}
		v, modPayload := w.handleUDP(streamID, ipFlow, tr, encap)
		// Modifying encapsulated packets is not currently supported
		if v == io.VerdictAcceptModify && modPayload != nil && encap == nil {
			tr.Payload = modPayload
			_ = tr.SetNetworkLayerForChecksum(netLayer)
			_ = w.modSerializeBuffer.Clear()
			err := gopacket.SerializePacket(w.modSerializeBuffer,
				gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}, p)
			if err != nil {
				// Just accept without modification for now
				return io.VerdictAccept, nil
			}
			return v, w.modSerializeBuffer.Bytes()
		}
		return v, nil
	default:
		// Unsupported protocol
		return io.VerdictAccept, nil
	}
}

func (w *worker) handleTCP(ipFlow gopacket.Flow, pMeta *gopacket.PacketMetadata, tcp *layers.TCP, encap analyzer.PropMap) io.Verdict {
	ctx := &tcpContext{
		PacketMetadata: pMeta,
		Verdict:        tcpVerdictAccept,
		Encap:          encap,
	}
	w.tcpAssembler.AssembleWithContext(ipFlow, tcp, ctx)
	return io.Verdict(ctx.Verdict)
}

func (w *worker) flushTCP(timeout time.Duration) {
	flushed, closed := w.tcpAssembler.FlushCloseOlderThan(time.Now().Add(-timeout))
	w.logger.TCPFlush(w.id, flushed, closed)
}

func (w *worker) handleUDP(streamID uint32, ipFlow gopacket.Flow, udp *layers.UDP, encap analyzer.PropMap) (io.Verdict, []byte) {
	ctx := &udpContext{
		Verdict: udpVerdictAccept,
		Encap:   encap,
	}
	w.udpStreamManager.MatchWithContext(streamID, ipFlow, udp, ctx)
	return io.Verdict(ctx.Verdict), ctx.Packet
}
