# ntop2ban —— 构建与发布
#
# 发布形态:ntop2ban 主二进制与官方 clickhouse 静态二进制同目录打包,
# ntop2ban 运行时把 clickhouse 作为子进程托管(见 README 的"拷贝即用")。
# clickhouse 二进制不入 git(200MB+),由 fetch-clickhouse 按需下载。

GO ?= go
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

BIN_DIR := bin
DIST_DIR := dist

# ClickHouse 官方静态二进制下载地址。单个文件既是 server 也是 client。
CH_URL ?= https://builds.clickhouse.com/master/amd64/clickhouse

.PHONY: all build test test-integration fetch-clickhouse release clean fmt vet check

all: build

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ntop2ban ./cmd/ntop2ban

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

# 单元测试:不需要任何外部依赖。ClickHouse 的集成测试会因为未设置
# NTOP2BAN_CH_TEST_ADDR 而自动 skip。
test:
	$(GO) test ./...

check: vet test

# 集成测试:用 bin/clickhouse 起一个临时实例再跑。先 make fetch-clickhouse。
# 端口用 19000 避开常规 9000,防止撞上机器上已有的 ClickHouse。
test-integration: $(BIN_DIR)/clickhouse
	@rm -rf /tmp/ntop2ban-citest && mkdir -p /tmp/ntop2ban-citest/log
	@printf '%s\n' \
	  '<clickhouse>' \
	  '  <logger><level>warning</level><log>/tmp/ntop2ban-citest/log/ch.log</log><errorlog>/tmp/ntop2ban-citest/log/ch.err.log</errorlog></logger>' \
	  '  <path>/tmp/ntop2ban-citest/</path><tmp_path>/tmp/ntop2ban-citest/tmp/</tmp_path>' \
	  '  <user_files_path>/tmp/ntop2ban-citest/user_files/</user_files_path>' \
	  '  <listen_host>127.0.0.1</listen_host><tcp_port>19000</tcp_port><http_port>18123</http_port>' \
	  '  <mark_cache_size>5368709120</mark_cache_size>' \
	  '</clickhouse>' > /tmp/ntop2ban-citest/config.xml
	@$(BIN_DIR)/clickhouse server --config-file=/tmp/ntop2ban-citest/config.xml \
	  > /tmp/ntop2ban-citest/log/stdout.log 2>&1 & echo $$! > /tmp/ntop2ban-citest/ch.pid
	@for i in $$(seq 1 30); do \
	  sleep 1; \
	  $(BIN_DIR)/clickhouse client --port 19000 --query "SELECT 1" >/dev/null 2>&1 && break; \
	done
	-NTOP2BAN_CH_TEST_ADDR=127.0.0.1:19000 $(GO) test ./internal/storage/clickhouse/... -v
	@kill $$(cat /tmp/ntop2ban-citest/ch.pid) 2>/dev/null || true

fetch-clickhouse: $(BIN_DIR)/clickhouse

$(BIN_DIR)/clickhouse:
	mkdir -p $(BIN_DIR)
	curl -fsSL -o $(BIN_DIR)/clickhouse $(CH_URL)
	chmod +x $(BIN_DIR)/clickhouse

# 交叉编译。注意 clickhouse 二进制是按架构分开的:arm64 发布包需要
# arm64 版的 clickhouse(CH_URL 里的 amd64 换成 aarch64),这里只编
# ntop2ban 本体,打包时各架构分别取对应的 clickhouse。
release: check
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/ntop2ban-linux-amd64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/ntop2ban-linux-arm64 ./cmd/ntop2ban
	cd $(DIST_DIR) && sha256sum ntop2ban-linux-* > SHA256SUMS

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
