package detection

import (
        "math"
        "testing"
)

// ─── Shannon entropy tests ────────────────────────────────────────────────────

func TestShannonEntropy_EmptyInput(t *testing.T) {
        got := shannonEntropy([]byte{})
        if got != 0.0 {
                t.Errorf("expected 0.0 for empty input, got %f", got)
        }
}

func TestShannonEntropy_AllSameByte(t *testing.T) {
        data := make([]byte, 128)
        // All zeros → single symbol → H = 0
        got := shannonEntropy(data)
        if got != 0.0 {
                t.Errorf("expected 0.0 for uniform input, got %f", got)
        }
}

func TestShannonEntropy_MaxEntropy(t *testing.T) {
        // 256 distinct byte values, one each → H = log2(256) = 8.0
        data := make([]byte, 256)
        for i := range data {
                data[i] = byte(i)
        }
        got := shannonEntropy(data)
        if math.Abs(got-8.0) > 0.001 {
                t.Errorf("expected ~8.0 for perfectly uniform input, got %f", got)
        }
}

func TestShannonEntropy_PlainText(t *testing.T) {
        // English-like text should have entropy < 5.0
        text := []byte("the quick brown fox jumps over the lazy dog 1234567890")
        // pad to 128 bytes
        for len(text) < 128 {
                text = append(text, ' ')
        }
        got := shannonEntropy(text[:128])
        if got >= 5.0 {
                t.Errorf("expected entropy < 5.0 for plain text, got %f", got)
        }
}

// ─── Detector.Analyze tests ───────────────────────────────────────────────────

func newTestDetector() *Detector {
        // entropy-only mode (no model file)
        return &Detector{threshold: 7.0, modelPath: "", hasModel: false}
}

func TestAnalyze_SafeWrite(t *testing.T) {
        d := newTestDetector()
        sample := make([]byte, 128) // all zeros → entropy = 0
        result := d.Analyze(sample, 512)
        if result.IsMalicious {
                t.Error("expected safe verdict for zero-byte sample")
        }
}

func TestAnalyze_MaliciousWrite(t *testing.T) {
        d := newTestDetector()
        // Near-uniform distribution → entropy ≈ 8.0
        sample := make([]byte, 128)
        for i := range sample {
                sample[i] = byte(i % 256)
        }
        result := d.Analyze(sample, 4096)
        if !result.IsMalicious {
                t.Errorf("expected malicious verdict for high-entropy sample, entropy=%.4f", result.Entropy)
        }
}

func TestAnalyze_BelowThreshold(t *testing.T) {
        d := &Detector{threshold: 7.0, hasModel: false}
        // 16 distinct values repeated → entropy = log2(16) = 4.0
        sample := make([]byte, 128)
        for i := range sample {
                sample[i] = byte(i % 16)
        }
        result := d.Analyze(sample, 128)
        if result.IsMalicious {
                t.Errorf("expected safe verdict for entropy=%.4f (threshold 7.0)", result.Entropy)
        }
}
