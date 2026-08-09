package enrich

// 应用分类。技术设计 §23 的优先级:端口 → 协议 → 已知签名 → 未来 DPI。
//
// 明确的边界:这是"按已知端口推断的应用",不是"确认的应用"。
// 设计文档特别强调不能把 dst_port=443 直接等同于 100% HTTPS ——
// 那个端口上跑什么都有可能。所以界面上这一列的标题是"应用(推断)",
// 而不是"应用"。
//
// 内嵌 IANA 服务名的一个子集而不是完整表:完整的 IANA 注册表有上万条,
// 绝大多数是没人用的历史注册。收录常见的几十个,其余归入
// "tcp/<端口>" 这种形式——后者比一个来自 1990 年代的冷门服务名更有信息量。

// 端口 → 应用名。只放真正常见的。
var tcpPorts = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 179: "bgp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	514: "syslog", 587: "smtp-submission", 636: "ldaps",
	873: "rsync", 989: "ftps-data", 990: "ftps", 993: "imaps", 995: "pop3s",
	1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
	1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
	2376: "docker-tls", 2379: "etcd", 3000: "grafana", 3128: "http-proxy",
	3306: "mysql", 3389: "rdp", 4444: "metasploit", 5000: "upnp",
	5432: "postgresql", 5060: "sip", 5432 + 1: "pgbouncer",
	5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-tls",
	6379: "redis", 6443: "kubernetes-api", 8000: "http-alt",
	8080: "http-proxy", 8086: "influxdb", 8123: "clickhouse-http",
	8443: "https-alt", 8888: "http-alt", 9000: "clickhouse",
	9042: "cassandra", 9092: "kafka", 9100: "node-exporter",
	9200: "elasticsearch", 9300: "elasticsearch-transport",
	11211: "memcached", 15672: "rabbitmq-mgmt",
	27017: "mongodb", 5601: "kibana",
}

var udpPorts = map[uint16]string{
	53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 123: "ntp",
	137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 162: "snmp-trap",
	443: "quic", 500: "ike", 514: "syslog", 520: "rip", 1194: "openvpn",
	1701: "l2tp", 1812: "radius", 1813: "radius-acct",
	2055: "netflow", 4500: "ipsec-nat-t", 4789: "vxlan",
	5060: "sip", 6081: "geneve", 6343: "sflow", 51820: "wireguard",
}

// Classify 推断应用。
//
// 先看目的端口再看源端口:客户端的源端口是随机高位端口,目的端口才是
// 服务端口。反过来看会把"某人访问 443"识别成"某人从 443 提供服务"。
//
// 两个端口都不认识时返回 "tcp/12345" 这种形式而不是空字符串或
// "unknown":空字符串会让 Top Application 里出现一个匿名的巨大条目,
// 而带端口号的形式仍然可以下钻——用户看到 "tcp/9999" 至少知道该去查
// 那个端口是什么。
func Classify(protocol uint8, srcPort, dstPort uint16) string {
	switch protocol {
	case 6: // TCP
		if name, ok := tcpPorts[dstPort]; ok {
			return name
		}
		if name, ok := tcpPorts[srcPort]; ok {
			return name
		}
		// 端口 0 出现在畸形包或非端口协议上,不该拼成 "tcp/0"
		if dstPort == 0 {
			return "tcp"
		}
		return "tcp/" + itoa(dstPort)

	case 17: // UDP
		if name, ok := udpPorts[dstPort]; ok {
			return name
		}
		if name, ok := udpPorts[srcPort]; ok {
			return name
		}
		if dstPort == 0 {
			return "udp"
		}
		return "udp/" + itoa(dstPort)

	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 89:
		return "ospf"
	case 132:
		return "sctp"
	case 2:
		return "igmp"
	default:
		return "proto/" + itoa(uint16(protocol))
	}
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
