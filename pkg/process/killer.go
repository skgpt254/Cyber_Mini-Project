// Package process provides process management utilities for the eRDS agent:
//   - KillProcess sends SIGKILL with full safety guards and deduplication.
//   - ReadCmdline reads /proc/[pid]/cmdline for rich alert context.
package process

import (
        "fmt"
        "os"
        "strings"
        "sync"
        "syscall"
)

// ─── Kill deduplication ───────────────────────────────────────────────────────

var (
        killedMu  sync.Mutex
        killedSet = make(map[int]struct{})
)

// ─── Public API ───────────────────────────────────────────────────────────────

// KillProcess sends SIGKILL to the given PID after passing all safety guards.
//
// Safety guards (in order):
//  1. PID 0  — kernel idle process, NEVER kill.
//  2. PID 1  — init / systemd, NEVER kill.
//  3. Self   — agent refuses to kill its own PID.
//  4. Dedup  — once a PID has been killed, skip subsequent kill attempts for
//     the same PID.  This prevents a flood of SIGKILL from a burst of
//     high-entropy ring-buffer events that all arrive before the process dies.
//  5. Liveness probe — signal(0) check before SIGKILL.  If the process is
//     already dead (reaped by the kernel), treat it as success and update
//     dedup state without emitting a spurious error.
func KillProcess(pid int) error {
        // Guard 1 & 2: Never kill the kernel idle process or init/systemd.
        if pid == 0 {
                return fmt.Errorf("refused to kill PID 0 (kernel idle process)")
        }
        if pid == 1 {
                return fmt.Errorf("refused to kill PID 1 (init/systemd)")
        }

        // Guard 3: Never kill ourselves.
        if pid == os.Getpid() {
                return fmt.Errorf("refused to kill own PID %d (self-kill protection)", pid)
        }

        // Guard 4: Deduplication — skip if already killed.
        killedMu.Lock()
        if _, alreadyKilled := killedSet[pid]; alreadyKilled {
                killedMu.Unlock()
                return fmt.Errorf("PID %d already killed (dedup skip)", pid)
        }
        killedSet[pid] = struct{}{}
        killedMu.Unlock()

        // Guard 5: Liveness probe — signal(0) checks existence without sending a
        // real signal.  ESRCH means the process no longer exists.
        proc, err := os.FindProcess(pid)
        if err != nil {
                return fmt.Errorf("could not find process %d: %v", pid, err)
        }

        if probeErr := proc.Signal(syscall.Signal(0)); probeErr != nil {
                // Process already gone — treat as success.
                return nil
        }

        // Send the real SIGKILL.
        if err := proc.Signal(syscall.SIGKILL); err != nil {
                return fmt.Errorf("failed to send SIGKILL to PID %d: %v", pid, err)
        }

        return nil
}

// ReadCmdline reads /proc/[pid]/cmdline and returns the full command line as a
// single space-separated string.  Returns "" on any error (process already
// gone, permission denied, etc.) — callers must treat "" as "unavailable".
func ReadCmdline(pid int) string {
        data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
        if err != nil {
                return ""
        }
        // /proc/[pid]/cmdline uses NUL bytes as argument separators.
        // Replace them with spaces and trim trailing whitespace.
        return strings.TrimRight(
                strings.ReplaceAll(string(data), "\x00", " "),
                " ",
        )
}
