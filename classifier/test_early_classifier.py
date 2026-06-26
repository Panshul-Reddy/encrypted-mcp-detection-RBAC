"""
Encrypted RBAC Demo - Access Control WITHOUT Decryption.

The ML model predicts which MCP server the encrypted traffic is destined for.
Combined with the source IP (from the TCP header), it enforces role-based
access control entirely at Layer 4. Zero decryption needed.

This script loads the ML model directly (no API needed) and runs predictions
against sample flows from the real dataset.

Usage:
    classifier\\.venv\\Scripts\\python.exe classifier\\test_early_classifier.py
"""

import os
import sys
import time
import json
import random

import numpy as np
import pandas as pd
import xgboost as xgb

# =============================================================================
# Constants (same as api.py)
# =============================================================================

LABEL_MAP = {
    0: "noise",
    1: "fetch",
    2: "memory",
    3: "filesystem",
    4: "github",
    5: "exa",
    6: "tavily",
}

# Role -> which predicted servers they are allowed to access
SERVER_POLICY = {
    "full":     ["fetch", "memory", "filesystem", "github", "exa", "tavily"],
    "analyst":  ["fetch", "filesystem", "exa", "tavily"],
    "readonly": ["fetch", "exa", "tavily"],
}

# Source IP -> Role mapping (extracted from TCP header, no decryption)
IP_ROLES = {
    "10.11.0.30": "full",       # Groq AI agent
    "10.11.0.40": "readonly",   # Noise / restricted client
    "127.0.0.1":  "full",       # Localhost
}

DEFAULT_ROLE = "readonly"
CONFIDENCE_THRESHOLD = 0.85

THRESHOLDS = [3, 5, 8, 10, 15, 20]


def get_features_for_n(n):
    """Return the feature columns available at packet N."""
    features = ["entropy"]
    for i in range(n):
        features.append(f"seq_size_{i:02d}")
        features.append(f"seq_dir_{i:02d}")
        features.append(f"seq_iat_{i:02d}")
    return features


def load_model(n):
    """Load a trained model for threshold N."""
    path = os.path.join("classifier", "models", f"xgb_n{n}.json")
    if not os.path.exists(path):
        path = os.path.join("models", f"xgb_n{n}.json")
    if not os.path.exists(path):
        return None
    m = xgb.XGBClassifier()
    m.load_model(path)
    return m


def load_dataset():
    """Load the real dataset."""
    for p in ["dataset.csv", "../dataset.csv"]:
        if os.path.exists(p):
            return pd.read_csv(p)
    return None


def make_rbac_decision(role, server_name, confidence):
    """Encrypted RBAC decision logic (confidence gating is handled by the caller)."""
    if server_name == "noise":
        return "PASS", "Traffic classified as non-MCP noise"
    
    allowed = SERVER_POLICY.get(role, [])
    if server_name in allowed:
        return "ALLOW", f"Role '{role}' is allowed to access server '{server_name}'"
    else:
        return "DENY", f"Role '{role}' is NOT allowed to access server '{server_name}' (allowed: {', '.join(allowed)})"


def run_demo():
    print()
    print("=" * 70)
    print("  ENCRYPTED RBAC DEMO - Access Control WITHOUT Decryption")
    print("=" * 70)
    print()
    print("  How it works:")
    print("  1. ML model predicts which server the ENCRYPTED traffic targets")
    print("  2. Source IP (from TCP header) determines the client's role")
    print("  3. Role + Predicted Server = ALLOW / DENY decision")
    print("  4. Zero decryption needed at any point")
    print()
    print("-" * 70)

    # Load dataset
    df = load_dataset()
    if df is None:
        print("  ERROR: dataset.csv not found!")
        return

    # Load models for different thresholds
    loaded_models = {}
    for n in THRESHOLDS:
        m = load_model(n)
        if m is not None:
            loaded_models[n] = m
    
    # Also load the full model for high-confidence classification
    for p in [os.path.join("classifier", "models", "xgb_full.json"), os.path.join("models", "xgb_full.json")]:
        if os.path.exists(p):
            m = xgb.XGBClassifier()
            m.load_model(p)
            loaded_models["full"] = m
            break
    
    if not loaded_models:
        print("  ERROR: No trained models found in classifier/models/")
        print("  Run: classifier\\.venv\\Scripts\\python.exe classifier\\train.py")
        return

    print(f"  Loaded models for thresholds: {list(loaded_models.keys())}")
    print()

    # Define test scenarios: (source_ip, n_packets, target_label, description)
    # target_label picks a real flow from the dataset with that label
    scenarios = [
        ("10.11.0.30", 20, 4, "Groq AI Agent accessing GitHub server"),
        ("10.11.0.30", 20, 3, "Groq AI Agent accessing Filesystem server"),
        ("10.11.0.40", 20, 2, "Restricted Client trying to access Memory server"),
        ("10.11.0.40", 20, 4, "Restricted Client trying to access GitHub server"),
        ("10.11.0.40", 20, 1, "Restricted Client accessing Fetch server (allowed)"),
        ("192.168.1.99", 20, 3, "Unknown Client (zero-trust) trying Filesystem"),
        ("192.168.1.99", 3,  5, "Unknown Client with very few packets (low confidence)"),
        ("10.11.0.40", 20, 0, "Restricted Client sending Noise traffic"),
    ]

    results = {"ALLOW": 0, "DENY": 0, "WAIT": 0, "PASS": 0}
    audit_log = []

    for i, (source_ip, n_packets, target_label, description) in enumerate(scenarios, 1):
        print(f"  Scenario {i}: {description}")
        print(f"  Source IP: {source_ip}  |  Packets: {n_packets}")

        # Pick a real flow from the dataset with the target label
        label_df = df[df["label"] == target_label]
        if len(label_df) == 0:
            print(f"  SKIP: No flows with label {target_label} in dataset")
            continue
        sample = label_df.sample(1).iloc[0]
        true_label = int(sample["label"])
        true_server = LABEL_MAP.get(true_label, "unknown")

        # Select best model: use full model for N>=20 for best accuracy
        if n_packets >= 20 and "full" in loaded_models:
            best_n = "full"
            all_feature_cols = [c for c in df.columns if c not in ["flow_display", "label"]]
            x = []
            for col in all_feature_cols:
                if col in sample.index:
                    x.append(float(sample[col]))
                else:
                    x.append(0.0)
        else:
            best_n = None
            for n in sorted(k for k in loaded_models.keys() if isinstance(k, int)):
                if n <= n_packets:
                    best_n = n
            if best_n is None:
                best_n = min(k for k in loaded_models.keys() if isinstance(k, int))
            feature_cols = get_features_for_n(best_n)
            x = []
            for col in feature_cols:
                if col in sample.index:
                    x.append(float(sample[col]))
                else:
                    x.append(0.0)

        model = loaded_models[best_n]
        x = np.array(x).reshape(1, -1)

        # Run ML prediction on the encrypted traffic features
        probas = model.predict_proba(x)[0]
        predicted_label = int(np.argmax(probas))
        confidence = float(max(probas))
        predicted_server = LABEL_MAP.get(predicted_label, "unknown")

        # Resolve role from IP (TCP header - no decryption)
        role = IP_ROLES.get(source_ip, DEFAULT_ROLE)

        # For early models (not full), apply confidence threshold.
        # The full model has ALL data — no more packets to wait for,
        # so it always makes a final decision.
        use_wait = (best_n != "full" and confidence < CONFIDENCE_THRESHOLD)

        # Make RBAC decision
        if use_wait:
            decision = "WAIT"
            reason = f"Confidence {confidence*100:.1f}% below {CONFIDENCE_THRESHOLD*100:.0f}% threshold, waiting for more packets"
        else:
            decision, reason = make_rbac_decision(role, predicted_server, confidence)
        results[decision] += 1

        # Display
        print(f"  ML Prediction: server='{predicted_server}' (confidence: {confidence*100:.1f}%) [model: N={best_n}]")
        print(f"  True Server:   '{true_server}' (from dataset label)")
        print(f"  Role resolved: '{role}' (from source IP, no decryption)")

        if decision == "ALLOW":
            marker = "[ALLOW]"
        elif decision == "DENY":
            marker = "[DENY ]"
        elif decision == "WAIT":
            marker = "[WAIT ]"
        else:
            marker = "[PASS ]"

        print(f"  RBAC Decision: {marker} {reason}")

        # Log it
        audit_log.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_ip": source_ip,
            "role": role,
            "predicted_server": predicted_server,
            "true_server": true_server,
            "confidence": round(confidence, 4),
            "model_n": best_n,
            "decision": decision,
            "reason": reason,
        })

        print(f"  {'_' * 60}")
        time.sleep(0.8)

    # Write audit log
    os.makedirs("logs", exist_ok=True)
    log_path = os.path.join("logs", "encrypted_rbac_audit.jsonl")
    with open(log_path, "w", encoding="utf-8") as f:
        for entry in audit_log:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")

    # Summary
    print()
    print("=" * 70)
    print("  SUMMARY - Encrypted RBAC Decisions (No Decryption)")
    print("=" * 70)
    print(f"  ALLOW : {results['ALLOW']}  (Role had permission for predicted server)")
    print(f"  DENY  : {results['DENY']}  (Role blocked from predicted server)")
    print(f"  WAIT  : {results['WAIT']}  (Confidence too low, need more packets)")
    print(f"  PASS  : {results['PASS']}  (Non-MCP noise traffic, ignored)")
    print(f"  Total : {sum(results.values())}")
    print()
    print("  Key insight: ALL decisions made on ENCRYPTED traffic.")
    print("  The ML model predicted the server. The IP determined the role.")
    print("  No payload was ever inspected or decrypted.")
    print()
    print(f"  Audit log saved to: {log_path}")
    print("=" * 70)
    print()


if __name__ == "__main__":
    run_demo()
