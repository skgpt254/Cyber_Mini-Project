import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import skl2onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import joblib

# --- 1. Generate Synthetic Training Data ---
# In a real scenario, you would load 'training_data.csv' collected by your agent.
# For now, we simulate data to ensure you have a working model immediately.

def generate_dummy_data(n_samples=2000):
    print(f"[*] Generating {n_samples} synthetic samples...")
    
    # Feature 1: Entropy (0.0 to 8.0)
    # Benign files (code, logs, text) usually have entropy < 6.0
    # Ransomware (encrypted) usually has entropy > 7.0
    benign_entropy = np.random.normal(loc=4.5, scale=1.0, size=n_samples // 2)
    malicious_entropy = np.random.normal(loc=7.8, scale=0.2, size=n_samples // 2)
    
    # Feature 2: Write Size (Bytes)
    # Benign: Varied, often small (logs) or medium (saving a doc)
    # Malicious: Often uniform, large blocks (4KB, 64KB) for encryption speed
    benign_size = np.random.randint(10, 5000, size=n_samples // 2)
    malicious_size = np.random.randint(4000, 8000, size=n_samples // 2)

    # Labels: 0 = Safe, 1 = Ransomware
    y = np.array([0] * (n_samples // 2) + [1] * (n_samples // 2))
    
    # Combine features
    X_entropy = np.concatenate([benign_entropy, malicious_entropy])
    X_size = np.concatenate([benign_size, malicious_size])
    
    # Create DataFrame
    df = pd.DataFrame({'entropy': X_entropy, 'write_size': X_size})
    
    # Clip entropy to valid range [0, 8]
    df['entropy'] = df['entropy'].clip(0, 8)
    
    return df, y

# --- 2. Train the Model ---

# Generate data
X, y = generate_dummy_data()

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("[*] Training Random Forest Classifier...")
clf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print(f"[*] Model Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# --- 3. Export to ONNX (The Bridge to Go) ---
print("[*] Converting model to ONNX format...")

# Define input type: A float tensor with 2 features (Entropy, Write Size)
initial_type = [('float_input', FloatTensorType([None, 2]))]

# Convert
onnx_model = convert_sklearn(clf, initial_types=initial_type)

# Save
output_path = "ransomware.onnx"
with open(output_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"[SUCCESS] Model saved to {output_path}")
print("You can now load this .onnx file in your Go agent!")
