package knock

import (
	"errors"
	"net"
	"testing"
	"time"
)

// nowForTest 给序列步骤一个单调递增但都在时限内的时间戳。
func nowForTest() time.Time { return time.Now() }

// buildICMPPacket 造一个 raw ICMP socket 会收到的包(带 IP 头)。
// payloadLen 就是客户端 `ping -s N` 的 N。
func buildICMPPacket(t *testing.T, src string, icmpType byte, payloadLen, ihlWords int) []byte {
	t.Helper()
	ihl := ihlWords * 4
	pkt := make([]byte, ihl+8+payloadLen)
	pkt[0] = 0x40 | byte(ihlWords)
	pkt[9] = 1 // IPPROTO_ICMP
	copy(pkt[12:16], net.ParseIP(src).To4())
	pkt[ihl] = icmpType
	return pkt
}

// TestParseICMPEchoReturnsPingDashSLength 这是整个 ICMP 敲门步的关键契约:
// 返回的长度必须与用户在界面上看到的 `ping -s N` 的 N 完全相同。
//
// 若这里返回的是含 ICMP 头(8 字节)的长度,用户照界面提示敲就永远敲不开,
// 而且没有任何线索说明差在哪——日志里只会显示"收到一个长度 64 的包",
// 用户以为自己敲的是 56。这类偏差 8 字节的 bug 极难被想到。
func TestParseICMPEchoReturnsPingDashSLength(t *testing.T) {
	for _, want := range []int{8, 56, 90, 1400} {
		pkt := buildICMPPacket(t, "203.0.113.7", 8, want, 5)
		src, got, err := parseICMPEcho(pkt)
		if err != nil {
			t.Fatalf("payloadLen=%d: %v", want, err)
		}
		if got != want {
			t.Errorf("长度应与 ping -s 的参数一致: want %d, got %d", want, got)
		}
		if !src.Equal(net.ParseIP("203.0.113.7")) {
			t.Errorf("src: want 203.0.113.7, got %s", src)
		}
	}
}

// TestParseICMPEchoIgnoresEchoReply echo reply(type 0)是本机 ping 别人
// 得到的回包。把它算进敲门会让本机自己发起的 ping 变成敲门事件——
// 一台正常做健康检查的机器会不停地"敲自己的门"。
func TestParseICMPEchoIgnoresEchoReply(t *testing.T) {
	pkt := buildICMPPacket(t, "203.0.113.7", 0, 56, 5)
	if _, _, err := parseICMPEcho(pkt); !errors.Is(err, errNotEchoRequest) {
		t.Fatalf("echo reply 应被忽略, got err=%v", err)
	}
}

// TestParseICMPEchoIgnoresOtherTypes 其他 ICMP 类型(如 3 目的不可达、
// 11 超时)也不该被当成敲门。
func TestParseICMPEchoIgnoresOtherTypes(t *testing.T) {
	for _, typ := range []byte{3, 5, 11, 13} {
		pkt := buildICMPPacket(t, "203.0.113.7", typ, 56, 5)
		if _, _, err := parseICMPEcho(pkt); err == nil {
			t.Errorf("ICMP type %d 不应被当成敲门步", typ)
		}
	}
}

// TestParseICMPEchoWithIPOptions IP 头带 option 时 ICMP 头位置后移,
// 必须按 IHL 动态定位,否则长度算错、type 也读错。
func TestParseICMPEchoWithIPOptions(t *testing.T) {
	pkt := buildICMPPacket(t, "192.0.2.9", 8, 56, 8)
	src, got, err := parseICMPEcho(pkt)
	if err != nil {
		t.Fatalf("parseICMPEcho: %v", err)
	}
	if got != 56 {
		t.Errorf("带 IP option 时长度算错: want 56, got %d", got)
	}
	if !src.Equal(net.ParseIP("192.0.2.9")) {
		t.Errorf("src: want 192.0.2.9, got %s", src)
	}
}

// TestParseICMPEchoRejectsTruncated 截断的包必须报错而不是越界 panic。
func TestParseICMPEchoRejectsTruncated(t *testing.T) {
	pkt := buildICMPPacket(t, "203.0.113.7", 8, 56, 5)
	for _, n := range []int{0, 10, 19, 20, 25} {
		if _, _, err := parseICMPEcho(pkt[:n]); err == nil {
			t.Errorf("截断到 %d 字节应报错", n)
		}
	}
}

// TestParseICMPEchoRejectsBadIHL IHL 小于 5 是非法的(IP 头至少 20 字节),
// 不检查会让后续切片偏移为负或指向错误位置。
func TestParseICMPEchoRejectsBadIHL(t *testing.T) {
	pkt := buildICMPPacket(t, "203.0.113.7", 8, 56, 5)
	pkt[0] = 0x42 // version 4, IHL=2 -> 8 字节,非法
	if _, _, err := parseICMPEcho(pkt); err == nil {
		t.Error("非法 IHL 应报错")
	}
}

// TestICMPStepMatchesSequenceValue 端到端语义检查:界面告诉用户敲
// `ping -s 56`,捕获层解析出 56,状态机就应该认为第 2 步命中。
// 这三者用的是同一个数字,这个测试把它们钉在一起。
func TestICMPStepMatchesSequenceValue(t *testing.T) {
	seq := demoSeq()
	m, log := newTestMatcher(t, seq)

	// 第 1 步是 TCP 9001
	frame := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9001, tcpSYN, 5, 0)
	src, port, err := parseTCPSYN(frame)
	if err != nil {
		t.Fatalf("parseTCPSYN: %v", err)
	}
	m.Feed(Observation{Source: src, Step: Step{Kind: StepTCP, Port: port}, At: nowForTest()})

	// 第 2 步:ping -s 56
	pkt := buildICMPPacket(t, "203.0.113.7", 8, 56, 5)
	isrc, plen, err := parseICMPEcho(pkt)
	if err != nil {
		t.Fatalf("parseICMPEcho: %v", err)
	}
	m.Feed(Observation{Source: isrc, Step: Step{Kind: StepICMP, PayloadLen: plen}, At: nowForTest()})

	// 第 3、4 步
	f3 := buildEthIPv4TCP(t, "203.0.113.7", "198.51.100.1", 40000, 9003, tcpSYN, 5, 0)
	s3, p3, _ := parseTCPSYN(f3)
	m.Feed(Observation{Source: s3, Step: Step{Kind: StepTCP, Port: p3}, At: nowForTest()})

	pkt4 := buildICMPPacket(t, "203.0.113.7", 8, 90, 5)
	s4, l4, _ := parseICMPEcho(pkt4)
	m.Feed(Observation{Source: s4, Step: Step{Kind: StepICMP, PayloadLen: l4}, At: nowForTest()})

	if len(*log) != 1 {
		t.Fatalf("按界面给出的命令敲完应放行 1 次, got %d", len(*log))
	}
}
