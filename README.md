<div align="center">

# eRDS  
## eBPF Ransomware Defense System

[![Languages](https://img.shields.io/badge/Languages-Go%20%7C%20C%20%7C%20Python-2C3E50.svg)](https://golang.org/)
[![Core](https://img.shields.io/badge/Core-eBPF-orange.svg)](https://ebpf.io/)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://kernel.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**Real-Time Ransomware Detection & Prevention  
via Kernel-Level Telemetry**

GLA University, Mathura  
Cyber Security Mini-Project — 2026

</div>

---

# Overview

Traditional antivirus solutions are reactive — they wait for signatures.

**eRDS is behavioral and proactive.**

Running inside the Linux kernel using eBPF, it observes file-write operations in real time and performs entropy analysis to detect encryption activity before widespread damage occurs.

---

# Team

| Role | Name | Responsibility |
|------|------|---------------|
| **Team Leader** | **Anav** | System Architecture, Core Logic, Project Coordination |
| **Member** | **Jay** | eBPF Kernel Hooks, C Implementation |
| **Member** | **Sandesh** | User-Space Agent, Golang Integration |
| **Member** | **Shantanu** | Testing, Simulation, Documentation |

---

# Architecture

eRDS follows a split-architecture model to balance performance, safety, and detection flexibility.

```mermaid
graph TD
    A[Ransomware Attack] -->|Writes Encrypted Data| B(Linux Kernel)
    B -->|Hooks sys_write| C{eBPF Program}
    C -->|Captures Data Sample| D[Ring Buffer]
    D -->|High-Speed Transfer| E[Go User Agent]
    E -->|Calculate Entropy| F{Malicious?}
    F -->|High Entropy| G[Terminate Process]
    F -->|Normal Data| H[Log as Safe]
````

---

## Kernel Layer — The Watcher

Attached to `sys_enter_write`.

For every file write:

* Intercepts syscall
* Filters irrelevant noise
* Captures a 128-byte sample
* Pushes data into a high-performance ring buffer

Built using eBPF CO-RE for portability across modern Linux kernels.

---

## User Layer — The Decision Engine

The Go agent asynchronously consumes events from the ring buffer.

It performs Shannon entropy analysis:

| Entropy Range | Interpretation                | Classification |
| ------------- | ----------------------------- | -------------- |
| 0.0 – 5.0     | Text / source / configuration | Safe           |
| 7.5 – 8.0     | High-density encrypted data   | Malicious      |

If entropy exceeds the threshold (7.5), the system sends `SIGKILL` to the offending PID.

---

# Core Features

* Lightweight kernel-level monitoring (eBPF CO-RE)
* Behavioral ransomware detection
* Millisecond-level response time
* Compatible with Linux kernel 5.8+
* No runtime kernel header dependency

---

# Project Structure

```bash
└── Cyber_Mini-Project
    ├── Makefile
    ├── bpf
    │   ├── headers
    │   ├── monitor.bpf.c
    │   └── vmlinux.h
    ├── cmd
    │   └── agent
    │       ├── gen.go
    │       ├── main.go
    │       ├── monitor_bpfel.go
    │       └── monitor_bpfel.o
    ├── dist
    │   └── ransomware-agent
    ├── go.mod
    ├── go.sum
    ├── model
    │   ├── ransomware.onnx
    │   └── train.py
    └── pkg
        ├── detection
        ├── ebpf
        └── process
```

---

# Installation

## Requirements

* Linux (Ubuntu 20.04+, Debian 11+, Kali)
* Kernel 5.8+
* Go 1.22+
* clang, llvm, bpftool, make

---

## Build Instructions

```bash
git clone https://github.com/skgpt254/Cyber_Mini-Project.git
cd Cyber_Mini-Project

sudo apt update
sudo apt install -y clang llvm libbpf-dev bpftool golang-go make

bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

make generate
make build

sudo ./dist/ransomware-agent
```

---

# Testing

⚠ Use only controlled simulations.

### Safe File

```bash
echo "This is a safe text file for the GLA project." > notes.txt
```

Expected: Logged as safe.

---

### Simulated Encryption Event

```bash
openssl rand -out encrypted_test.bin 4096
```

Expected:

```
[ALERT] High Entropy detected
[MITIGATED] Process terminated
```

---

# Roadmap

* Replace static entropy threshold with ONNX Random Forest model
* Honeyfile deployment
* Command & Control (C2) outbound blocking
* Web-based monitoring dashboard

---

# Contributing

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push branch
5. Submit pull request

---

# License

Distributed under MIT License. See `LICENSE` for details.

---

<div align="center">

**Secure the Kernel. Secure the System.**

</div>
