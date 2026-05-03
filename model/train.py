#!/usr/bin/env python3
"""

Labels:
  0 = Benign   (plain text, structured binaries, logs)
  1 = Ransomware (high-entropy bulk-encryption writes)

Output: ransomware.onnx  (saved to the model/ directory next to this script)

Usage:
  pip install scikit-learn skl2onnx pandas numpy --break-system-packages
  python3 model/train.py
"""

import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# ─── 1. Synthetic training data ───────────────────────────────────────────────

def generate_data(n_samples: int = 4000, seed: int = 42) -> tuple:
    """
    Generates balanced synthetic training data.

    Benign distribution:
      entropy  ~ Normal(4.5, 1.2)   — text, ELF, JSON, log files
      size     ~ Uniform(10, 5000)  — small log writes to medium saves

    Malicious distribution:
      entropy  ~ Normal(7.8, 0.15)  — AES-CBC / ChaCha20 ciphertext
      size     ~ Uniform(4000, 8000)— bulk encryption block writes

    Both are clipped to physically meaningful ranges.
    """
    rng = np.random.default_rng(seed)
    half = n_samples // 2

    print(f"[*] Generating {n_samples} synthetic samples (seed={seed})…")

    # Benign
    benign_entropy = rng.normal(loc=4.5, scale=1.2, size=half).clip(0.0, 8.0)
    benign_size    = rng.integers(10, 5000, size=half).astype(float)

    # Malicious
    malicious_entropy = rng.normal(loc=7.8, scale=0.15, size=half).clip(0.0, 8.0)
    malicious_size    = rng.integers(4000, 8001, size=half).astype(float)

    X = pd.DataFrame({
        "entropy":    np.concatenate([benign_entropy,    malicious_entropy]),
        "write_size": np.concatenate([benign_size,       malicious_size]),
    })
    y = np.array([0] * half + [1] * half)

    return X, y


# ─── 2. Train ─────────────────────────────────────────────────────────────────

X, y = generate_data()

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("[*] Training Random Forest (100 trees, max_depth=6)…")
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=6,
    min_samples_leaf=5,
    random_state=42,
    n_jobs=-1,
)
clf.fit(X_train, y_train)

# ─── 3. Evaluate ──────────────────────────────────────────────────────────────

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"[*] Test accuracy : {acc:.4f}")
print()
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Benign", "Ransomware"]))

if acc < 0.90:
    print("[WARN] Accuracy below 90% — consider tuning hyperparameters or using real data.")
    sys.exit(1)

# ─── 4. Export to ONNX ────────────────────────────────────────────────────────

print("[*] Converting to ONNX…")

# Input: float32 tensor with shape [N, 2]
initial_type = [("float_input", FloatTensorType([None, 2]))]
onnx_model = convert_sklearn(clf, initial_types=initial_type, target_opset=17)

# Save next to this script (i.e. model/ransomware.onnx)
script_dir  = os.path.dirname(os.path.abspath(__file__))
output_path = os.path.join(script_dir, "ransomware.onnx")

with open(output_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"[OK] Saved: {output_path}")
print("     Feature order: [entropy (float32), write_size (float32)]")
print("     Output classes: 0=Benign, 1=Ransomware")
