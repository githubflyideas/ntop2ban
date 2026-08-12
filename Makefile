# ntop2ban —— 单一二进制
#
# 最终用户只需要 `make build`(或直接 go build):编译好的 eBPF 目标文件
# 已提交进版本库,不需要 clang。只有改动 bpf/*.c 的维护者才需要
# `make bpf`,并且 CI 会用 `make bpf-verify` 确认 .o 与 .c 没有漂移。
#
# CGO_ENABLED=0 是硬约束:SQLite 用 modernc.org/sqlite(纯 Go),
# 因此能静态编译、scp 到目标机直接运行。

GO ?= go
CLANG ?= clang
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

BPF_SRC := bpf/sampler.c
BPF_OBJ := internal/datasource/obj/sampler.o
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Werror

.PHONY: build test check fmt vet bpf bpf-verify release package verify-packages clean

build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o ntop2ban ./cmd/ntop2ban

test:
	$(GO) test ./...

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

check: vet test

## bpf: 编译 XDP 程序。产物提交进库(见 internal/datasource/embed.go 的说明)。
bpf:
	@command -v $(CLANG) >/dev/null || \
	  { echo "缺少 $(CLANG)。安装:apt-get install clang libbpf-dev"; exit 1; }
	mkdir -p $(dir $(BPF_OBJ))
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@ls -l $(BPF_OBJ)

## bpf-verify: 重新编译并与库里的 .o 比对。CI 跑这个,防止改了 .c 忘了重编——
## 那样 .o 与 .c 会静默漂移,运行时行为与源码不符,极难排查。
bpf-verify:
	@command -v $(CLANG) >/dev/null || \
	  { echo "跳过 bpf-verify:本机没有 $(CLANG)"; exit 0; }
	@mkdir -p /tmp/ntop2ban-bpfverify
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o /tmp/ntop2ban-bpfverify/sampler.o
	@if ! cmp -s /tmp/ntop2ban-bpfverify/sampler.o $(BPF_OBJ); then \
	  echo "$(BPF_OBJ) 与 $(BPF_SRC) 不一致 —— 请执行 make bpf 并提交产物"; exit 1; \
	fi
	@echo "bpf 目标文件与源码一致"

## release: 打出各平台的发行二进制。
##
## 每个包里是 ntop2ban + 对应架构的 clickhouse 静态二进制,解压即可运行。
## clickhouse 按需下载(不入库,200MB 级),CH_URL_AMD64/ARM64 可覆盖。
##
## amd64 用官方的 **amd64compat** 构建,不是 amd64。
##
## 理由:默认的 amd64 构建要求 x86-64-v2(SSE4.2/POPCNT),在较老的物理机
## 与屏蔽了这些指令的虚拟机上一执行就被内核 SIGILL 掉,表现为
## "Illegal instruction (core dumped)"。用最激进的构建去打一个
## "拷过去就跑"的包,本身就与那个承诺矛盾——而用户拿到的错误信息完全
## 指不到"换个 clickhouse 构建"这个方向。amd64compat 是纯 SSE2 构建,
## 牺牲一点性能换普遍可运行,对单机部署这是正确的取舍。
CH_URL_LINUX_AMD64  ?= https://builds.clickhouse.com/master/amd64compat/clickhouse
CH_URL_LINUX_ARM64  ?= https://builds.clickhouse.com/master/aarch64/clickhouse
CH_URL_DARWIN_ARM64 ?= https://builds.clickhouse.com/master/macos-aarch64/clickhouse
## Intel Mac 的目录名是 macos,不是 macos-x86_64 —— 后者 403,别照着
## aarch64 那个命名去猜。
CH_URL_DARWIN_AMD64 ?= https://builds.clickhouse.com/master/macos/clickhouse

## darwin 产物与 Linux 产物功能对等:v0.5.0 起 macOS 上的 -input local
## 走 /dev/bpf,本机抓包是支持的。缺的只有 XDP(那是 Linux 内核接口),
## 表现为 Mac 上只有一级采集层可用。
release: check
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-amd64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-arm64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-darwin-arm64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-darwin-amd64 ./cmd/ntop2ban
	cd dist && sha256sum ntop2ban-linux-* ntop2ban-darwin-* > SHA256SUMS

## package: 组装"解压即跑"的大包 —— 每个包里是 ntop2ban + 同架构的
## clickhouse 自解压二进制 + 一页 README.txt,单个 160~185MB。
##
## 为什么值得出这么大的包:目标使用者是家用 NAS 与 Mac(见 README),那些
## 机器上装 ClickHouse 要么没有现成的包,要么要先装 docker。让人拷一个目录
## 进去就能跑起来,是这个项目最省事的入口。已经有 ClickHouse 实例的人走
## 裸二进制 + -clickhouse-addr,两条路并存。
##
## 按架构分别下载 —— arm64 包里放 amd64 的二进制会在目标机上直接 exec
## 失败,而那个错误很难让人想到是打包错了。打完包 verify-packages 会用
## file(1) 复核每个包里两个二进制的架构,别跳过。
##
## gzip 用 -1:clickhouse 那个自解压二进制本身已经是压缩数据,更高的级别
## 只是白烧 CPU,换不到几 MB。
PKG_TARGETS := linux-amd64 linux-arm64 darwin-arm64 darwin-amd64

package: release
	@set -e; rm -rf dist/pkg; mkdir -p dist/pkg; \
	for t in $(PKG_TARGETS); do \
	  case $$t in \
	    linux-amd64)  url="$(CH_URL_LINUX_AMD64)";; \
	    linux-arm64)  url="$(CH_URL_LINUX_ARM64)";; \
	    darwin-arm64) url="$(CH_URL_DARWIN_ARM64)";; \
	    darwin-amd64) url="$(CH_URL_DARWIN_AMD64)";; \
	    *) echo "未知打包目标 $$t"; exit 1;; \
	  esac; \
	  name=ntop2ban-$$t; d=dist/pkg/$$name; mkdir -p $$d; \
	  cp dist/$$name $$d/ntop2ban; \
	  case $$t in \
	    darwin-*) cp packaging/README-darwin.txt $$d/README.txt;; \
	    *)        cp packaging/README-linux.txt  $$d/README.txt;; \
	  esac; \
	  echo ">> 下载 $$t 版 clickhouse"; \
	  curl -fSL --retry 3 -o $$d/clickhouse "$$url" || { echo "下载失败: $$url"; exit 1; }; \
	  chmod +x $$d/clickhouse; \
	  tar --use-compress-program='gzip -1' -cf dist/$$name.tar.gz -C dist/pkg $$name; \
	  rm -rf $$d; \
	  echo ">> $$name.tar.gz $$(du -h dist/$$name.tar.gz | cut -f1)"; \
	done; \
	rmdir dist/pkg
	cd dist && sha256sum ntop2ban-*.tar.gz >> SHA256SUMS
	@ls -lh dist/*.tar.gz

## verify-packages: 复核每个包里的 ntop2ban 与 clickhouse 是不是同一个
## 架构、同一个操作系统。打错架构的包在开发机上看不出任何异常,只有目标机
## 会报 exec format error,所以这一步必须在上传之前跑。
verify-packages:
	@set -e; for t in $(PKG_TARGETS); do \
	  echo "== ntop2ban-$$t.tar.gz"; \
	  rm -rf /tmp/n2b-verify && mkdir -p /tmp/n2b-verify; \
	  tar xzf dist/ntop2ban-$$t.tar.gz -C /tmp/n2b-verify; \
	  file /tmp/n2b-verify/ntop2ban-$$t/ntop2ban /tmp/n2b-verify/ntop2ban-$$t/clickhouse \
	    | sed "s|/tmp/n2b-verify/ntop2ban-$$t/||"; \
	done; rm -rf /tmp/n2b-verify

clean:
	rm -rf dist ntop2ban
