# ARP Sniffer



### 项目简介
ARP Sniffer 是一个基于Go语言开发的网络嗅探工具，可以通过ARP欺骗技术监听局域网内的数据流量。该工具主要用于网络安全测试和教育目的，可以帮助网络管理员了解网络安全风险，提高安全意识。

### 功能特点
- ARP欺骗：能够通过发送虚假的ARP数据包，将自己伪装成网关
- 数据包嗅探：捕获网络中的敏感数据包，特别是登录凭证信息
- 支持多目标：可以同时监听多个IP地址的流量
- 自动恢复：程序终止时会自动修复ARP缓存，减少对网络的影响
- 跨平台支持：可在Windows、Linux等多种操作系统上运行

### 安装说明
1. 确保已安装Go环境（1.16或更高版本）
2. 克隆仓库到本地
   ```bash
   git clone https://github.com/yourusername/ARP_Sniffer.git
   cd ARP_Sniffer
   ```
3. 安装依赖库
   ```bash
   go mod tidy
   ```
4. 编译程序
   ```bash
   go build
   ```

### 使用方法
#### Linux系统
```bash
sudo ./arp_sniffer -target 192.168.1.100-192.168.1.110 -gateway 192.168.1.1 -i eth0
```

#### Windows系统
```bash
arp_sniffer.exe -target 192.168.1.100-192.168.1.110 -gateway 192.168.1.1 -i WLAN
```

### 参数说明
- `-target`：目标IP范围，可以是单个IP、IP范围或CIDR格式（如192.168.1.0/24）
- `-gateway`：网关IP地址
- `-i`：网卡接口名称，不指定则使用默认活动网卡
- `-l`：显示可用网卡列表

### 注意事项
- 本工具仅用于合法的网络安全测试和教育用途
- 在使用前请确保获得网络管理员的授权
- 在Linux系统下需要以root权限运行
- 使用过程中可能会对网络性能造成一定影响

### 测试展示

![image](https://github.com/user-attachments/assets/51ce80b4-be25-4171-88c3-d3db021e3496)


![image](https://github.com/user-attachments/assets/c0487095-972e-4d28-b93c-9675ccfae09f)
ARP欺骗成功

![image](https://github.com/user-attachments/assets/b0c3e5e4-2535-4319-9be0-feedd95a0ce0)


成功捕获到敏感信息

## ARP Sniffer

### Project Introduction
ARP Sniffer is a network sniffing tool developed in Go language that can monitor network traffic within a LAN through ARP spoofing techniques. This tool is primarily designed for network security testing and educational purposes, helping network administrators understand security risks and raise security awareness.

### Features
- ARP Spoofing: Ability to disguise itself as the gateway by sending fake ARP packets
- Packet Sniffing: Captures sensitive data packets in the network, especially login credential information
- Multi-target Support: Can monitor traffic from multiple IP addresses simultaneously
- Automatic Recovery: Automatically repairs ARP cache upon program termination, reducing impact on the network
- Cross-platform Support: Can run on Windows, Linux, and other operating systems

### Installation
1. Ensure Go environment is installed (version 1.16 or higher)
2. Clone the repository
   ```bash
   git clone https://github.com/yourusername/ARP_Sniffer.git
   cd ARP_Sniffer
   ```
3. Install dependencies
   ```bash
   go mod tidy
   ```
4. Build the program
   ```bash
   go build
   ```

### Usage
#### Linux
```bash
sudo ./arp_sniffer -target 192.168.1.100-192.168.1.110 -gateway 192.168.1.1 -i eth0
```

#### Windows
```bash
arp_sniffer.exe -target 192.168.1.100-192.168.1.110 -gateway 192.168.1.1 -i WLAN
```

### Parameters
- `-target`: Target IP range, can be a single IP, IP range, or CIDR format (e.g., 192.168.1.0/24)
- `-gateway`: Gateway IP address
- `-i`: Network interface name, uses the default active interface if not specified
- `-l`: Display available network interfaces

### Precautions
- This tool is intended only for legitimate network security testing and educational purposes
- Ensure you have authorization from the network administrator before use
- Root privileges are required on Linux systems
- The tool may have some impact on network performance during operation

### Test Demonstration
![image](https://github.com/user-attachments/assets/0b1b9413-ac73-45be-b246-60cda3dbe8d3)
![image](https://github.com/user-attachments/assets/e8e8a61a-cf35-4037-b229-5c2f8df30617)


ARP spoofing successful
![image](https://github.com/user-attachments/assets/af500542-44de-433a-8931-55da9e186962)


Successfully captured sensitive information

