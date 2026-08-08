package knock

import "testing"

// nft -a list chain 的真实输出形态。handle 在行尾的 `# handle N`。
const sampleNFTOutput = `table inet ntop2ban {
	chain knock { # handle 2
		type filter hook input priority -10; policy accept;
		ip saddr 203.0.113.7 tcp dport 22 accept comment "ntop2ban-knock" # handle 4
		ip saddr 198.51.100.9 tcp dport 22 accept comment "ntop2ban-knock" # handle 5
		ip saddr 203.0.113.7 tcp dport 2222 accept comment "ntop2ban-knock" # handle 6
	}
}
`

func TestScanHandleFindsExactRule(t *testing.T) {
	cases := []struct {
		src  string
		port int
		want string
	}{
		{"203.0.113.7", 22, "4"},
		{"198.51.100.9", 22, "5"},
		{"203.0.113.7", 2222, "6"},
	}
	for _, tc := range cases {
		got := scanHandle(sampleNFTOutput, tc.src, tc.port)
		if got != tc.want {
			t.Errorf("scanHandle(%s, %d) = %q, want %q", tc.src, tc.port, got, tc.want)
		}
	}
}

// TestScanHandleMissReturnsEmpty 找不到时返回空串,调用方据此视为
// "规则已经不在了",而不是去删一个不存在的 handle(那会报错)。
func TestScanHandleMissReturnsEmpty(t *testing.T) {
	if h := scanHandle(sampleNFTOutput, "192.0.2.1", 22); h != "" {
		t.Errorf("不存在的规则应返回空串, got %q", h)
	}
	if h := scanHandle(sampleNFTOutput, "203.0.113.7", 8080); h != "" {
		t.Errorf("端口不匹配应返回空串, got %q", h)
	}
}

// TestScanHandleOnlyTouchesOwnRules 这是最重要的一条:只删自己打了
// comment 标记的规则。
//
// 用户手工加的、恰好同源同端口的 accept 规则必须不被我们碰到——
// 删掉用户自己的防火墙规则是不可接受的副作用,而且用户完全不会想到
// 是敲门组件干的。
func TestScanHandleOnlyTouchesOwnRules(t *testing.T) {
	userRule := `table inet ntop2ban {
	chain knock { # handle 2
		ip saddr 203.0.113.7 tcp dport 22 accept # handle 9
	}
}
`
	if h := scanHandle(userRule, "203.0.113.7", 22); h != "" {
		t.Errorf("没有 ntop2ban-knock 标记的规则不应被认领, got handle %q", h)
	}
}

// TestScanHandleDoesNotMatchPortSubstring dport 22 不应匹配到 dport 2222。
// 用裸字符串包含判断很容易犯这个错,结果是删错规则。
func TestScanHandleDoesNotMatchPortSubstring(t *testing.T) {
	only2222 := `table inet ntop2ban {
	chain knock { # handle 2
		ip saddr 203.0.113.7 tcp dport 2222 accept comment "ntop2ban-knock" # handle 6
	}
}
`
	if h := scanHandle(only2222, "203.0.113.7", 22); h != "" {
		t.Errorf("dport 22 不应匹配 dport 2222 那一行, got handle %q", h)
	}
}
