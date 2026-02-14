# Variables
CLANG ?= clang
GO ?= go

.PHONY: all generate build clean

all: generate build

# 1. Compile C -> BPF Bytecode -> Go Structs
generate:
	cd cmd/agent && $(GO) generate

# 2. Compile Go Agent -> Binary
build:
	$(GO) build -o dist/ransomware-agent ./cmd/agent

clean:
	rm -rf dist
	rm -f cmd/agent/monitor_bpfel.go cmd/agent/monitor_bpfel.o
