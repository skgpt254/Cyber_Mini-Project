package main

// This command compiles the C code when you run 'go generate'
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -output-dir . monitor ../../bpf/monitor.bpf.c
