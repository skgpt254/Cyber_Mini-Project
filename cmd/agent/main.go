package main

import (
        "bytes"
        "encoding/binary"
        "fmt"
        "log"
        "os"
        "os/signal"
        "path/filepath"
        "syscall"

        "github.com/cilium/ebpf/link"
        "github.com/cilium/ebpf/ringbuf"
        "github.com/cilium/ebpf/rlimit"

        "github.com/skgpt254/ransomware-defense/pkg/detection"
        "github.com/skgpt254/ransomware-defense/pkg/process"
)

// Event MUST exactly match struct event_t in monitor.bpf.c.
//
//      u32  pid         offset   0
//      u32  uid         offset   4
//      char comm[16]    offset   8
//      u64  write_len   offset  24
//      u64  fd          offset  32
//      u8   sample[512] offset  40
//      Total = 552 bytes
type Event struct {
        Pid      uint32
        Uid      uint32
        Comm     [16]byte
        WriteLen uint64
        Fd       uint64
        Sample   [512]byte
}

// entropyThreshold — writes with entropy above this are suspicious.
// 7.0 works well for VirtualBox where we use /proc fallback reads.
const entropyThreshold = 7.0

var processWhitelist = map[string]struct{}{
        "zip": {}, "gzip": {}, "bzip2": {}, "xz": {}, "zstd": {},
        "7z": {}, "7za": {}, "scp": {}, "sftp": {}, "ssh": {},
        "gpg": {}, "gpg2": {}, "ffmpeg": {}, "age": {},
        "chrome": {}, "firefox": {},
}

func main() {
        fmt.Println()
        fmt.Println("  ╔══════════════════════════════════════════════╗")
        fmt.Println("  ║   eRDS — eBPF Ransomware Defense System      ║")
        fmt.Println("  ║   GLA University, Mathura  ·  2026           ║")
        fmt.Println("  ╚══════════════════════════════════════════════╝")
        fmt.Println()

        if err := rlimit.RemoveMemlock(); err != nil {
                log.Fatalf("[FATAL] Failed to remove memlock limit: %v", err)
        }

        objs := monitorObjects{}
        if err := loadMonitorObjects(&objs, nil); err != nil {
                log.Fatalf("[FATAL] Failed to load eBPF objects: %v\n       → Run: make generate", err)
        }
        defer objs.Close()

        kpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
        if err != nil {
                log.Fatalf("[FATAL] Failed to attach sys_enter_write: %v", err)
        }
        defer kpWrite.Close()

        kpPwrite, err := link.Tracepoint("syscalls", "sys_enter_pwrite64", objs.TracePwrite64, nil)
        if err != nil {
                fmt.Printf("⚠️   pwrite64 hook unavailable: %v\n", err)
        } else {
                defer kpPwrite.Close()
        }

        rd, err := ringbuf.NewReader(objs.Events)
        if err != nil {
                log.Fatalf("[FATAL] Failed to open ring buffer: %v", err)
        }
        defer rd.Close()

        modelPath := findModelPath()
        detector := detection.NewDetector(entropyThreshold, modelPath)

        fmt.Printf("🤖  ML model       : %s\n", detector.ModelStatus())
        fmt.Printf("🛡️   Monitoring     : sys_enter_write + sys_enter_pwrite64\n")
        fmt.Printf("📊  Entropy cutoff : %.1f bits/byte\n", entropyThreshold)
        fmt.Printf("✅  Whitelisted    : %d processes\n", len(processWhitelist))
        fmt.Printf("🔒  Safety guards  : PID0/PID1/self-kill + dedup active\n")
        fmt.Println("   Press Ctrl-C to stop.")
        fmt.Println()

        go func() {
                sig := make(chan os.Signal, 1)
                signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
                <-sig
                fmt.Println("\n[INFO] Shutting down eRDS gracefully...")
                rd.Close()
        }()

        for {
                record, err := rd.Read()
                if err != nil {
                        if err == ringbuf.ErrClosed {
                                fmt.Println("[INFO] Ring buffer closed. Exiting.")
                                return
                        }
                        continue
                }

                var event Event
                if err := binary.Read(
                        bytes.NewBuffer(record.RawSample),
                        binary.LittleEndian,
                        &event,
                ); err != nil {
                        continue
                }

                comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
                pid := int(event.Pid)

                // Stage 0: Whitelist — skip instantly
                if _, ok := processWhitelist[comm]; ok {
                        continue
                }

                // Get the data sample for entropy analysis.
                // Primary: bytes captured by eBPF probe (fast, zero-copy).
                // Fallback: read file via /proc/PID/fd/N (works in VirtualBox
                //           where bpf_probe_read_user returns zeros).
                sample := event.Sample[:]
                source := "ebpf"
                if isAllZeros(sample) {
                        sample = readFdSample(pid, int(event.Fd), 512)
                        source = "proc"
                }

                result := detector.Analyze(sample, int64(event.WriteLen))

                _ = source // debug logging disabled in production — uncomment line below to enable
                // fmt.Printf("[DBG] pid=%-6d comm=%-15s fd=%-3d len=%-6d src=%-4s entropy=%.4f malicious=%v\n",

                if result.IsMalicious {
                        cmdline := process.ReadCmdline(pid)
                        fmt.Println()
                        fmt.Printf("🚨 [ALERT]    High entropy write detected!\n")
                        fmt.Printf("   PID       : %d\n", pid)
                        fmt.Printf("   Process   : %s\n", comm)
                        fmt.Printf("   UID       : %d\n", event.Uid)
                        fmt.Printf("   FD        : %d\n", event.Fd)
                        fmt.Printf("   Entropy   : %s (%.4f bits/byte)\n", result.EntropyLabel, result.Entropy)
                        fmt.Printf("   Reason    : %s\n", result.Reason)
                        fmt.Printf("   Write len : %d bytes\n", event.WriteLen)
                        if cmdline != "" {
                                fmt.Printf("   Cmdline   : %s\n", cmdline)
                        }
                        if err := process.KillProcess(pid); err != nil {
                                fmt.Printf("   ⚠️  [WARN]   %v\n\n", err)
                        } else {
                                fmt.Printf("   ✅ [KILLED]  PID %d terminated successfully.\n\n", pid)
                        }
                }
        }
}

// isAllZeros returns true if every byte is 0x00.
// Detects failed bpf_probe_read_user (common in VirtualBox).
func isAllZeros(b []byte) bool {
        for _, v := range b {
                if v != 0 {
                        return false
                }
        }
        return true
}

// readFdSample reads up to n bytes from /proc/PID/fd/FD.
// This fallback always works as root, even when eBPF userspace
// memory reads fail due to hypervisor restrictions.
func readFdSample(pid, fd, n int) []byte {
        // /proc/PID/fd/N is a symlink to the file — open and read beginning
        path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
        f, err := os.Open(path)
        if err != nil {
                return make([]byte, n)
        }
        defer f.Close()

        buf := make([]byte, n)
        nr, _ := f.Read(buf)
        if nr == 0 {
                return make([]byte, n)
        }
        return buf[:nr]
}

func findModelPath() string {
        candidates := []string{
                "model/ransomware.onnx",
                "../model/ransomware.onnx",
                filepath.Join(filepath.Dir(os.Args[0]), "../model/ransomware.onnx"),
                filepath.Join(filepath.Dir(os.Args[0]), "model/ransomware.onnx"),
        }
        for _, p := range candidates {
                if _, err := os.Stat(p); err == nil {
                        return p
                }
        }
        return ""
}
