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

.PHONY: build test check fmt vet bpf bpf-verify release clean

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

release: check
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-amd64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-arm64 ./cmd/ntop2ban
	cd dist && sha256sum ntop2ban-linux-* > SHA256SUMS

clean:
	rm -rf dist ntop2ban
