"""
FastFlow Early Inference API (Machine Learning Engine)

This module implements an asynchronous FastAPI server that hosts pre-trained tree
ensemble sequence models. It provides low-latency inference for the Rust feature
extractor, dynamically selecting the appropriate N-packet threshold model based on
the number of observed packets in the network flow.
"""

from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
import os
import sys
import time
import json
from typing import Optional

app = FastAPI(title="FastFlow Early Inference API")

THRESHOLDS = [3, 5, 8, 10, 15, 20]
models = {}

# =============================================================================
# Encrypted RBAC — No Decryption Required (Layer 4)
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

SERVER_POLICY = {
    "full": ["fetch", "memory", "filesystem", "github", "exa", "tavily"],
    "analyst": ["fetch", "filesystem", "exa", "tavily"],
    "readonly": ["fetch", "exa", "tavily"],
}

IP_ROLES = {
    "10.11.0.30": "full",
    "10.11.0.40": "readonly",
    "127.0.0.1":  "full",
}

DEFAULT_ROLE = "readonly"
CONFIDENCE_THRESHOLD = 0.40
RBAC_LOG_PATH = os.path.join("..", "logs", "encrypted_rbac_audit.jsonl")


def load_serialized_model(path: str):
    if path.endswith(".joblib"):
        return joblib.load(path)

    import xgboost as xgb

    model = xgb.XGBClassifier()
    model.load_model(path)
    return model

def get_feature_indices(n: int) -> list[int]:
    """
    Maps the progressive feature indices to the 115-dimension array sent by the Rust core.
    """
    indices = list(range(15)) # Base 15 features
    for i in range(n):
        indices.append(15 + i) # seq_size
        indices.append(35 + i) # seq_dir
        indices.append(55 + i) # seq_iat
    return indices

@app.on_event("startup")
def load_models():
    for n in THRESHOLDS:
        path = f"models/n{n}.joblib"
        legacy_path = f"models/xgb_n{n}.json"
        if os.path.exists(path):
            m = load_serialized_model(path)
            models[n] = m
            print(f"Loaded N={n} model.")
        elif os.path.exists(legacy_path):
            m = load_serialized_model(legacy_path)
            models[n] = m
            print(f"Loaded N={n} model.")
    full_path = "models/full.joblib"
    legacy_full_path = "models/xgb_full.json"
    if os.path.exists(full_path):
        m = load_serialized_model(full_path)
        models["full"] = m
        print("Loaded Full model.")
    elif os.path.exists(legacy_full_path):
        m = load_serialized_model(legacy_full_path)
        models["full"] = m
        print("Loaded Full model.")

class PredictRequest(BaseModel):
    features: list[float]
    source_ip: Optional[str] = None

class PredictBatchRequest(BaseModel):
    batch: list[PredictRequest]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/predict")
def predict(req: PredictRequest):
    feat = req.features
    if len(feat) != 115:
        return {"error": f"Expected 115 features, got {len(feat)}"}
    
    # We dynamically decide which model to use based on the number of non-zero packets
    # In Rust, total_pkts is index 1
    total_pkts = int(feat[1])
    
    # Find the largest threshold model that we can use
    target_n = None
    for n in reversed(THRESHOLDS):
        if total_pkts >= n and n in models:
            target_n = n
            break
            
    # ── Encrypted RBAC Decision ──
    source_ip = req.source_ip or ""
    
    role = IP_ROLES.get(source_ip, DEFAULT_ROLE)
    
    # [DEMO HACK] If all traffic originates from localhost, simulate different roles 
    # based on the first inter-arrival time to keep it pseudo-random but consistent per flow
    if source_ip == "127.0.0.1":
        iat = int(feat[56] * 1000000) if len(feat) > 56 else 0
        if iat == 0:
            role = "full"
        elif iat % 3 == 0:
            role = "analyst"
        elif iat % 3 == 1:
            role = "restricted"
        else:
            role = "full"
            
    if target_n is None:
        _log_rbac_decision(source_ip, role, "unknown", 0.0, "WAIT", "Waiting for more packets", "CLASSIFIED")
        return {
            "label": -1, 
            "proba": [0.0, 0.0],
            "rbac_decision": "WAIT",
            "rbac_reason": "Waiting for more packets"
        }
            
    model = models[target_n]
    
    if target_n != "full":
        indices = get_feature_indices(target_n)
        x = np.array([feat[i] for i in indices]).reshape(1, -1)
    else:
        x = np.array(feat).reshape(1, -1)

    probas = model.predict_proba(x)[0]
    
    # Classes: 0 is noise, 1-6 are MCP.
    noise_prob = float(probas[0])
    mcp_prob = float(sum(probas[1:]))

    # Handle probability dilution across multiple classes.
    # Instead of argmax across all 7 classes, check if the combined MCP probability 
    # beats Noise. If it does, find the most likely MCP class.
    if mcp_prob > noise_prob:
        label = int(np.argmax(probas[1:]) + 1)
    else:
        label = 0
    
    confidence = float(max(probas))
    server_name = LABEL_MAP.get(label, "unknown")

    # Progressive Confidence Thresholding
    if target_n != "full":
        # Dynamic threshold based on number of packets
        # For 7 classes, random is ~14%. 
        required_conf = {3: 0.35, 5: 0.40, 8: 0.45, 10: 0.50, 15: 0.55, 20: 0.60}.get(target_n, 0.40)
        
        if max(probas) < required_conf:
            # use previously defined source_ip and role
            _log_rbac_decision(source_ip, role, server_name, confidence, "WAIT", f"Confidence {confidence*100:.1f}% below threshold, waiting for more packets", "CLASSIFIED")
            return {
                "label": -1,
                "proba": [noise_prob, mcp_prob] if 'noise_prob' in locals() else probas.tolist(),
                "rbac_decision": "WAIT",
                "rbac_reason": f"Confidence {confidence*100:.1f}% below threshold, waiting for more packets"
            }

    # use previously defined source_ip and role
    
    # Base RBAC logic
    if server_name == "noise":
        rbac_decision = "PASS"
        rbac_reason = "Traffic classified as non-MCP noise"
    else:
        allowed_servers = SERVER_POLICY.get(role, [])
        if server_name in allowed_servers:
            rbac_decision = "ALLOW"
            rbac_reason = f"Role '{role}' is allowed to access server '{server_name}'"
        else:
            rbac_decision = "DENY"
            rbac_reason = f"Role '{role}' is NOT allowed to access server '{server_name}' (allowed: {', '.join(allowed_servers)})"

    _log_rbac_decision(source_ip, role, server_name, confidence, rbac_decision, rbac_reason, "CLASSIFIED")

    return {
        "label": label,
        "proba": [noise_prob, mcp_prob],
        "rbac_decision": rbac_decision,
        "rbac_reason": rbac_reason
    }

@app.post("/predict_batch")
def predict_batch(req: PredictBatchRequest):
    predictions = [None] * len(req.batch)
    groups = {}
    
    for idx, item in enumerate(req.batch):
        feat = item.features
        if len(feat) != 115:
            predictions[idx] = {"error": f"Expected 115 features, got {len(feat)}"}
            continue
            
        total_pkts = int(feat[1])
        target_n = None
        for n in reversed(THRESHOLDS):
            if total_pkts >= n and n in models:
                target_n = n
                break
                
        if target_n is None:
            source_ip = item.source_ip or ""
            role = IP_ROLES.get(source_ip, DEFAULT_ROLE)
            _log_rbac_decision(source_ip, role, "unknown", 0.0, "WAIT", "Waiting for more packets", "CLASSIFIED")
            predictions[idx] = {
                "label": -1, 
                "proba": [0.0, 0.0],
                "rbac_decision": "WAIT",
                "rbac_reason": "Waiting for more packets"
            }
            continue
            
        groups.setdefault(target_n, []).append((idx, item))
        
    for target_n, items in groups.items():
        indices = [item[0] for item in items]
        feats = [item[1].features for item in items]
        ips = [item[1].source_ip or "" for item in items]
        
        model = models[target_n]
        if target_n != "full":
            feat_indices = get_feature_indices(target_n)
            x = np.array([[f[i] for i in feat_indices] for f in feats])
        else:
            x = np.array(feats)
            
        probas_batch = model.predict_proba(x)
        
        for i, probas, ip in zip(indices, probas_batch, ips):
            noise_prob = float(probas[0])
            mcp_prob = float(sum(probas[1:]))
            
            if mcp_prob > noise_prob:
                label = int(np.argmax(probas[1:]) + 1)
            else:
                label = 0
                
            server_name = LABEL_MAP.get(label, "unknown")
            confidence = float(max(probas))
            
            if not ip:
                ip = "127.0.0.1"
                
            role = IP_ROLES.get(ip, DEFAULT_ROLE)
            
            if server_name == "noise":
                rbac_decision = "PASS"
                rbac_reason = "Noise"
            else:
                allowed_servers = SERVER_POLICY.get(role, [])
                if server_name in allowed_servers:
                    rbac_decision = "ALLOW"
                    rbac_reason = f"Role '{role}' allowed"
                else:
                    rbac_decision = "DENY"
                    rbac_reason = f"Role '{role}' denied"

            _log_rbac_decision(ip, role, server_name, confidence, rbac_decision, rbac_reason, "CLASSIFIED")
                
            predictions[i] = {
                "label": int(label),
                "proba": [noise_prob, mcp_prob],
                "rbac_decision": rbac_decision,
                "rbac_reason": rbac_reason
            }
            
    return {"predictions": predictions}

def _log_rbac_decision(source_ip, role, server, confidence, decision, reason, action):
    os.makedirs(os.path.dirname(RBAC_LOG_PATH) or ".", exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_ip": source_ip,
        "role": role,
        "predicted_server": server,
        "confidence": round(confidence, 4),
        "decision": decision,
        "reason": reason,
        "action": action,
    }
    try:
        with open(RBAC_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception as e:
        print(f"Failed to write RBAC log: {e}", file=sys.stderr)

