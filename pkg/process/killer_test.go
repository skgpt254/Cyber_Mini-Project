package process

import (
        "os"
        "strings"
        "testing"
)

func TestKillProcess_GuardPID0(t *testing.T) {
        err := KillProcess(0)
        if err == nil {
                t.Fatal("expected error when killing PID 0")
        }
        if !strings.Contains(err.Error(), "PID 0") {
                t.Errorf("expected PID 0 guard message, got: %v", err)
        }
}

func TestKillProcess_GuardPID1(t *testing.T) {
        err := KillProcess(1)
        if err == nil {
                t.Fatal("expected error when killing PID 1")
        }
        if !strings.Contains(err.Error(), "PID 1") {
                t.Errorf("expected PID 1 guard message, got: %v", err)
        }
}

func TestKillProcess_GuardSelf(t *testing.T) {
        err := KillProcess(os.Getpid())
        if err == nil {
                t.Fatal("expected error when killing own PID")
        }
        if !strings.Contains(err.Error(), "self-kill") {
                t.Errorf("expected self-kill guard message, got: %v", err)
        }
}

func TestKillProcess_DeduplicateSamePID(t *testing.T) {
        // Use an impossible PID to avoid actually killing anything.
        // The dedup guard fires after the safety guards, so we need a PID
        // that passes guards 1-3 but is then deduplicated on the second call.
        // We use our own PID+1 which is unlikely to be a real process in tests.
        // The first call will fail (process not found) after dedup records it.
        // The second call should return a "dedup skip" error.

        // Reset killed set for a clean test
        killedMu.Lock()
        delete(killedSet, 999999)
        killedMu.Unlock()

        // First call: will fail at FindProcess, but dedup entry is added
        _ = KillProcess(999999)

        // Second call: must be dedup skip
        err := KillProcess(999999)
        if err == nil {
                t.Fatal("expected dedup error on second kill of same PID")
        }
        if !strings.Contains(err.Error(), "dedup") {
                t.Errorf("expected dedup message, got: %v", err)
        }
}

func TestReadCmdline_Self(t *testing.T) {
        // Reading our own cmdline should succeed and be non-empty
        cmdline := ReadCmdline(os.Getpid())
        if cmdline == "" {
                t.Error("expected non-empty cmdline for own PID")
        }
}

func TestReadCmdline_NonExistentPID(t *testing.T) {
        // Should return "" gracefully without panicking
        cmdline := ReadCmdline(999999)
        if cmdline != "" {
                t.Errorf("expected empty string for non-existent PID, got: %q", cmdline)
        }
}
