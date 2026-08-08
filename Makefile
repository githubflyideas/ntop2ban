# ntop2ban —— 单一二进制,纯 Go,无外部依赖
#
# CGO_ENABLED=0 是硬约束:SQLite 用 modernc.org/sqlite(纯 Go 实现),
# 因此可以静态编译、scp 到目标机直接运行。这也是搬 pingping 探测能力
# 过来时不能直接复用它 store.go 的原因——那边用的 mattn/go-sqlite3
# 是 cgo 驱动,带进来就毁掉了这个属性。

GO ?= go
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check fmt vet release clean

build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o ntop2ban ./cmd/ntop2ban

test:
	$(GO) test ./...

fmt:
	gofmt -l -w .

vet:
	$(GO) vet ./...

check: vet test

release: check
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-amd64 ./cmd/ntop2ban
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/ntop2ban-linux-arm64 ./cmd/ntop2ban
	cd dist && sha256sum ntop2ban-linux-* > SHA256SUMS

clean:
	rm -rf dist ntop2ban
