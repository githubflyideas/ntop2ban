package storage

import (
	"github.com/githubflyideas/ntop2ban/internal/storage/clickhouse"
	"github.com/githubflyideas/ntop2ban/internal/storage/sqlite"
)

// 编译期断言:两个后端都必须实现 FlowStorage。
//
// 这类断言的价值在于把"某个方法签名改了但漏改了其中一个实现"这种
// 错误提前到编译期——否则只有在 main.go 里把具体实现赋给接口变量时
// 才会暴露,而那可能是很久以后。放在 storage 包内,让接口与其实现的
// 一致性成为本包的编译前提。
var (
	_ FlowStorage = (*clickhouse.Store)(nil)
	_ FlowStorage = (*sqlite.Store)(nil)
)
