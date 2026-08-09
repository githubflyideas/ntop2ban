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

.PHONY: build test check fmt vet bpf bpf-verify release package clean

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

## release: 打出两个架构的发行包。
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
CH_URL_AMD64 ?= https://builds.clickhouse.com/master/amd64compat/clickhouse
CH_URL_ARM64 ?= https://builds.clickhouse.com/master/aarch64/clickhouse

release: check
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-amd64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-arm64 ./cmd/ntop2ban
	cd dist && sha256sum ntop2ban-linux-* > SHA256SUMS

## package: 组装成 tar.gz。分架构下载 clickhouse —— arm64 包里放 amd64 的
## 二进制会在目标机上直接 exec 失败,而那个错误很难让人想到是打包错了。
package: release
	@for arch in amd64 arm64; do \
	  d=dist/ntop2ban-linux-$$arch.d; \
	  rm -rf $$d && mkdir -p $$d; \
	  cp dist/ntop2ban-linux-$$arch $$d/ntop2ban; \
	  url=$(CH_URL_AMD64); [ $$arch = arm64 ] && url=$(CH_URL_ARM64); \
	  echo ">> 下载 $$arch 版 clickhouse"; \
	  curl -fsSL -o $$d/clickhouse $$url || { echo "下载失败: $$url"; exit 1; }; \
	  chmod +x $$d/clickhouse; \
	  ( cd dist && mv ntop2ban-linux-$$arch.d ntop2ban-linux-$$arch-pkg \
	    && tar czf ntop2ban-linux-$$arch.tar.gz --transform "s|^ntop2ban-linux-$$arch-pkg|ntop2ban-linux-$$arch|" ntop2ban-linux-$$arch-pkg \
	    && rm -rf ntop2ban-linux-$$arch-pkg ); \
	done
	cd dist && sha256sum ntop2ban-linux-*.tar.gz >> SHA256SUMS
	@ls -lh dist/*.tar.gz

clean:
	rm -rf dist ntop2ban
