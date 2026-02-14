package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "math"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

// Must match C struct structure exactly
type Event struct {
    Pid      uint32
    WriteLen uint64
    Comm     [16]byte
    Sample   [128]byte // The data sample
}

func main() {
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock limit: %v", err)
    }

    objs := monitorObjects{}
    if err := loadMonitorObjects(&objs, nil); err != nil {
        log.Fatalf("Failed to load eBPF objects: %v", err)
    }
    defer objs.Close()

    kp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
    if err != nil {
        log.Fatalf("Failed to attach tracepoint: %v", err)
    }
    defer kp.Close()

    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        log.Fatalf("Failed to open ringbuf: %v", err)
    }
    defer rd.Close()

    log.Println("🛡️  Ransomware Defense Active. Monitoring Entropy...")

    // Graceful shutdown
    go func() {
        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
        <-sig
        log.Println("Stopping...")
        os.Exit(0)
    }()

    // Event Loop
    for {
        record, err := rd.Read()
        if err != nil {
            if err == ringbuf.ErrClosed { return }
            continue
        }

        // Parse binary data into struct
        var event Event
        if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
            continue
        }
        
        // Clean up process name
        comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
        
        // 1. Calculate Entropy
        entropy := calculateEntropy(event.Sample[:])

        // 2. The Decision Logic (Heuristic for now)
        // If Entropy is > 7.5 (Looks encrypted) AND it's not a known safe tool
        if entropy > 7.5 && comm != "zip" && comm != "gzip" && comm != "scp" {
            
            fmt.Printf("🚨 [DANGER] High Entropy (%.2f) detected from PID: %d (%s)\n", entropy, event.Pid, comm)
            
            // 3. KILL SWITCH
            killProcess(int(event.Pid))
        } else {
            // Optional: Print safe writes to verify it's working
            // fmt.Printf("[SAFE] PID: %d | Comm: %s | Entropy: %.2f\n", event.Pid, comm, entropy)
        }
    }
}

// Shannon Entropy Calculation (0.0 low -> 8.0 high)
func calculateEntropy(data []byte) float64 {
    if len(data) == 0 { return 0 }
    
    freqs := make(map[byte]float64)
    for _, b := range data {
        freqs[b]++
    }

    entropy := 0.0
    total := float64(len(data))
    for _, count := range freqs {
        p := count / total
        entropy -= p * math.Log2(p)
    }
    return entropy
}

func killProcess(pid int) {
    p, err := os.FindProcess(pid)
    if err != nil {
        return
    }
    // Kill immediately with SIGKILL (-9)
    if err := p.Signal(syscall.SIGKILL); err == nil {
        fmt.Printf("❌ [KILLED] Terminated Ransomware Process PID %d successfully.\n", pid)
    } else {
        fmt.Printf("⚠️ [FAIL] Could not kill PID %d: %v\n", pid, err)
    }
}
