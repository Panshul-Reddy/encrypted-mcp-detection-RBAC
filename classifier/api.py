"""
FastFlow Early Inference API (Machine Learning Engine)

This module implements an asynchronous FastAPI server that hosts pre-trained tree
ensemble sequence models. It provides low-latency inference for the Rust feature
extractor, dynamically selecting the appropriate N-packet threshold model based on
the number of observed packets in the network flow.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import joblib
import numpy as np
import os
import sys
import time
import json
import uuid
from collections import deque
from typing import Optional

app = FastAPI(title="FastFlow Early Inference API")

THRESHOLDS = [3, 5, 8, 10, 15, 20]
models = {}
flow_log = deque(maxlen=200)

def infer_ground_truth(dst_port: int, dst_ip: str = "") -> str:
    noise_ports = {9444}
    mcp_backend_ports = {3000, 3001, 3002, 3003, 3004, 3005}

    if dst_port in noise_ports:
        return "NOISE"
    if dst_port in mcp_backend_ports:
        return "MCP"
    return "UNKNOWN"

def log_classification(src_ip, src_port, dst_ip, dst_port,
                       prediction_label, rbac_decision, confidence, model_used, packet_count, feats, provided_gt=None):
    gt = provided_gt if provided_gt else infer_ground_truth(dst_port)
    
    # Normalize prediction for UI
    if rbac_decision == "WAIT":
        prediction = "Unknown_wait"
    elif prediction_label == "noise":
        prediction = "normal"
    else:
        prediction = "MCP_encrypted"
        
    pred_normalized = "MCP" if prediction == "MCP_encrypted" else prediction
    
    match_val = None
    if prediction != "Unknown_wait":
        match_val = (pred_normalized == gt)
        
    flow_log.appendleft({
        "id": str(uuid.uuid4())[:8],
        "ts": time.strftime("%H:%M:%S"),
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "ground_truth": gt,
        "prediction": prediction,
        "match": match_val,
        "model": f"N={model_used}" if str(model_used).isdigit() else model_used,
        "confidence": round(float(confidence), 3),
        "packet_count": packet_count,
        "features": feats[:55] # send first 55 features for the UI visualization (base 15 + seq_size 20 + seq_dir 20)
    })

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

import yaml

CONFIDENCE_THRESHOLD = 0.40
RBAC_LOG_PATH = os.path.join("..", "logs", "encrypted_rbac_audit.jsonl")

# Load unified policy
POLICY_PATH = os.path.join("..", "proxy", "tool_policy.yaml")
SERVER_POLICY = {}
IP_ROLES = {}
DEFAULT_ROLE = "readonly"

def load_policy():
    global SERVER_POLICY, IP_ROLES, DEFAULT_ROLE
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        if not config or "roles" not in config:
            raise ValueError("Policy file exists but has no 'roles:' key. "
                             "Check tool_policy.yaml structure.")

        IP_ROLES = config.get("clients", {}).get("by_ip", {})
        DEFAULT_ROLE = config.get("clients", {}).get("default_role", "readonly")
        roles = config.get("roles", {})
        SERVER_POLICY.clear()

        for rname, rdef in roles.items():
            if isinstance(rdef, dict):
                tools = rdef.get("allowed_tools", [])
                if tools == "*":
                    SERVER_POLICY[rname] = ["fetch", "memory", "filesystem",
                                            "github", "exa", "tavily"]
                elif isinstance(tools, list):
                    SERVER_POLICY[rname] = tools
                else:
                    SERVER_POLICY[rname] = []

        if not SERVER_POLICY:
            raise ValueError("No roles with 'allowed_tools' found in policy file.")

        print(f"[policy] Loaded {len(SERVER_POLICY)} roles from {POLICY_PATH}",
              file=sys.stderr)

    except FileNotFoundError:
        print(f"[policy] WARNING: {POLICY_PATH} not found. Using hardcoded fallback.",
              file=sys.stderr)
        _apply_fallback_policy()
    except Exception as e:
        print(f"[policy] ERROR: {e}. Using hardcoded fallback.", file=sys.stderr)
        _apply_fallback_policy()


def _apply_fallback_policy():
    """Fallback used only when policy file is missing or malformed."""
    global SERVER_POLICY, IP_ROLES, DEFAULT_ROLE
    SERVER_POLICY = {
        "full":     ["fetch", "memory", "filesystem", "github", "exa", "tavily"],
        "analyst":  ["fetch", "exa", "tavily"],
        "readonly": ["fetch"],
    }
    IP_ROLES = {
        "10.11.0.30": "full",
        "127.0.0.1":  "full",
    }
    DEFAULT_ROLE = "readonly"

DST_PORT_ROLES = {
    8440: "full",
    8441: "analyst",
    8442: "analyst",
    8443: "readonly",
    8444: "readonly",
    8445: "readonly",
    8446: "noise",
}

load_policy()

def _log_rbac_decision(source_ip, role, server, confidence, decision, reason, action, **kwargs):
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
    entry.update(kwargs)
    try:
        with open(RBAC_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception as e:
        pass


def load_serialized_model(path: str):
    if path.endswith(".joblib"):
        return joblib.load(path)
    
    import xgboost as xgb
    model = xgb.XGBClassifier()
    model.load_model(path)
    return model

def select_target_model(total_pkts: int):
    """
    Returns the best model key for a given packet count.
    Tries the highest N-model whose threshold is met first.
    Falls back to 'full' only if explicitly >= 30 packets AND full model exists.
    N=20 model is correctly used for 20-29 packet flows.
    """
    # First: check per-N thresholds (in descending order)
    for n in reversed(THRESHOLDS):   # [20, 15, 10, 8, 5, 3]
        if total_pkts >= n and n in models:
            # For 30+ packets, upgrade to full model if available
            if total_pkts >= 30 and "full" in models:
                return "full"
            return n
    # Not enough packets for any model yet
    return None

def resolve_role(source_ip: str, src_port: int, feat: list[float]) -> str:
    """
    On localhost (127.0.0.1), all clients share the same IP.
    We distinguish them by their SOURCE port ranges instead of Destination port.
    """
    if source_ip == "127.0.0.1":
        if 55000 <= src_port <= 59999: return "full"
        if 45000 <= src_port <= 49999: return "analyst"
        # Everything else (like default dynamic ports) is readonly
        return "readonly"
    return IP_ROLES.get(source_ip, DEFAULT_ROLE)

def required_confidence(target_n):
    if target_n == "full":
        return 0.0
    return {3: 0.35, 5: 0.40, 8: 0.45, 10: 0.50, 15: 0.55, 20: 0.60}.get(target_n, 0.40)

def get_feature_indices(n: int) -> list[int]:
    """
    Build the feature index list for an N-packet model.

    Feature layout in the 115-dim array:
      [0..15]   Base flow statistics (15 features)
      [15..35]  Sequence packet sizes   — seq_size_00 at index 15
      [35..55]  Sequence packet dirs    — seq_dir_00  at index 35
      [55..75]  Sequence IATs           — seq_iat_00  at index 55 (ALWAYS 0.0)
                                        — seq_iat_01  at index 56 (first real IAT)

    NOTE: seq_iat_00 (index 55) is hardcoded to 0.0 in features.rs because the
    first packet has no prior packet to measure against. We skip index 55 and
    start IATs from index 56 to avoid feeding a constant-zero feature.
    """
    indices = list(range(15))  # Base 15 features
    for i in range(n):
        indices.append(15 + i)       # seq_size[0..n-1]
        indices.append(35 + i)       # seq_dir[0..n-1]
        indices.append(56 + i)       # seq_iat[1..n]  — skip index 55 (always 0)
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
    src_port: Optional[int] = 0
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = 0
    ground_truth: Optional[str] = None

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
    target_n = select_target_model(total_pkts)
            
    # ── Encrypted RBAC Decision ──
    source_ip = req.source_ip or ""
    dst_port = req.dst_port or 0
    role = resolve_role(source_ip, dst_port, feat)
            
    if target_n is None:
        total_bytes = int(sum(feat[15:35]))
        _log_rbac_decision(source_ip, role, "unknown", 0.0, "WAIT", "Waiting for more packets", "CLASSIFIED",
                           packet_count=total_pkts, total_bytes=total_bytes, ground_truth=req.ground_truth if req.ground_truth else infer_ground_truth(dst_port), model="None", dst_port=dst_port)
        log_classification(req.source_ip or "?", req.src_port or 0, req.dst_ip or "?", req.dst_port or 0,
                           "unknown", "WAIT", 0.0, "None", total_pkts, feat, provided_gt=req.ground_truth)
        return {
            "label": -1, 
            "proba": [0.0, 0.0],
            "rbac_decision": "WAIT",
            "rbac_reason": "Waiting for more packets",
            "server_name": "unknown",
            "role": role
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
    if mcp_prob > noise_prob:
        label = int(np.argmax(probas[1:]) + 1)
        confidence = mcp_prob
    else:
        label = 0
        confidence = noise_prob
    
    server_name = LABEL_MAP.get(label, "unknown")

    # Noise always passes — skip threshold gate for noise
    if server_name == "noise":
        rbac_decision = "PASS"
        rbac_reason = "Traffic classified as non-MCP noise"
    else:
        # Progressive Confidence Thresholding for MCP
        min_conf = required_confidence(target_n)
        if target_n != "full" and confidence < min_conf:
            total_bytes = int(sum(feat[15:35]))
            _log_rbac_decision(source_ip, role, server_name, confidence, "WAIT", f"Confidence {confidence*100:.1f}% below threshold, waiting for more packets", "CLASSIFIED",
                               packet_count=total_pkts, total_bytes=total_bytes, ground_truth=req.ground_truth if req.ground_truth else infer_ground_truth(dst_port), model=target_n, dst_port=dst_port)
            log_classification(req.source_ip or "?", req.src_port or 0, req.dst_ip or "?", req.dst_port or 0,
                               server_name, "WAIT", confidence, target_n, total_pkts, feat, provided_gt=req.ground_truth)
            return {
                "label": -1,
                "proba": [noise_prob, mcp_prob],
                "rbac_decision": "WAIT",
                "rbac_reason": f"Confidence {confidence*100:.1f}% below threshold, waiting for more packets",
                "server_name": server_name,
                "role": role
            }

        # Base RBAC logic
        allowed_servers = SERVER_POLICY.get(role, [])
        if server_name in allowed_servers:
            rbac_decision = "ALLOW"
            rbac_reason = f"Role '{role}' is allowed to access server '{server_name}'"
        else:
            rbac_decision = "DENY"
            rbac_reason = f"Role '{role}' is NOT allowed to access server '{server_name}' (allowed: {', '.join(allowed_servers)})"

    total_bytes = int(sum(feat[15:35]))
    _log_rbac_decision(source_ip, role, server_name, confidence, rbac_decision, rbac_reason, "CLASSIFIED",
                       packet_count=total_pkts, total_bytes=total_bytes, ground_truth=req.ground_truth if req.ground_truth else infer_ground_truth(dst_port), model=target_n, dst_port=dst_port)
    log_classification(req.source_ip or "?", req.src_port or 0, req.dst_ip or "?", req.dst_port or 0,
                       server_name, rbac_decision, confidence, target_n, total_pkts, feat, provided_gt=req.ground_truth)

    return {
        "label": label,
        "proba": [noise_prob, mcp_prob],
        "rbac_decision": rbac_decision,
        "rbac_reason": rbac_reason,
        "server_name": server_name,
        "role": role
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
        target_n = select_target_model(total_pkts)
                
        if target_n is None:
            source_ip = item.source_ip or ""
            dst_port = item.dst_port or 0
            role = resolve_role(source_ip, dst_port, feat)
            total_bytes = int(sum(feat[15:35]))
            _log_rbac_decision(source_ip, role, "unknown", 0.0, "WAIT", "Waiting for more packets", "CLASSIFIED",
                               packet_count=total_pkts, total_bytes=total_bytes, ground_truth=item.ground_truth if item.ground_truth else infer_ground_truth(dst_port), model="None", dst_port=dst_port)
            log_classification(item.source_ip or "?", item.src_port or 0, item.dst_ip or "?", item.dst_port or 0,
                               "unknown", "WAIT", 0.0, "None", total_pkts, feat, provided_gt=item.ground_truth)
            predictions[idx] = {
                "label": -1, 
                "proba": [0.0, 0.0],
                "rbac_decision": "WAIT",
                "rbac_reason": "Waiting for more packets",
                "server_name": "unknown",
                "role": role
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
        
        orig_items = [item[1] for item in items]
        
        for i, probas, ip, feat, orig_req in zip(indices, probas_batch, ips, feats, orig_items):
            try:
                noise_prob = float(probas[0])
                mcp_prob = float(sum(probas[1:]))
                
                if mcp_prob > noise_prob:
                    label = int(np.argmax(probas[1:]) + 1)
                    confidence = mcp_prob
                else:
                    label = 0
                    confidence = noise_prob
                    
                server_name = LABEL_MAP.get(label, "unknown")
                
                if not ip:
                    ip = "127.0.0.1"
                
                dst_port = orig_req.dst_port or 0
                role = resolve_role(ip, dst_port, feat)
                total_pkts = int(feat[1])
                
                if server_name == "noise":
                    rbac_decision = "PASS"
                    rbac_reason = "Noise"
                else:
                    # Progressive Confidence Thresholding for MCP
                    min_conf = required_confidence(target_n)
                    if target_n != "full" and confidence < min_conf:
                        total_bytes = int(sum(feat[15:35]))
                        _log_rbac_decision(ip, role, server_name, confidence, "WAIT", f"Confidence {confidence*100:.1f}% below threshold", "CLASSIFIED",
                                           packet_count=total_pkts, total_bytes=total_bytes, ground_truth=orig_req.ground_truth if orig_req.ground_truth else infer_ground_truth(dst_port), model=target_n, dst_port=dst_port)
                        log_classification(orig_req.source_ip or "?", orig_req.src_port or 0, orig_req.dst_ip or "?", orig_req.dst_port or 0,
                                           server_name, "WAIT", confidence, target_n, total_pkts, feat, provided_gt=orig_req.ground_truth)
                        predictions[i] = {
                            "label": -1,
                            "proba": [noise_prob, mcp_prob],
                            "rbac_decision": "WAIT",
                            "rbac_reason": f"Confidence {confidence*100:.1f}% below threshold",
                            "server_name": server_name,
                            "role": role
                        }
                        continue

                    # Base RBAC logic
                    allowed_servers = SERVER_POLICY.get(role, [])
                    if server_name in allowed_servers:
                        rbac_decision = "ALLOW"
                        rbac_reason = f"Role '{role}' allowed"
                    else:
                        rbac_decision = "DENY"
                        rbac_reason = f"Role '{role}' denied"

                total_bytes = int(sum(feat[15:35]))
                _log_rbac_decision(ip, role, server_name, confidence, rbac_decision, rbac_reason, "CLASSIFIED",
                                   packet_count=total_pkts, total_bytes=total_bytes, ground_truth=orig_req.ground_truth if orig_req.ground_truth else infer_ground_truth(dst_port), model=target_n, dst_port=dst_port)
                log_classification(orig_req.source_ip or "?", orig_req.src_port or 0, orig_req.dst_ip or "?", orig_req.dst_port or 0,
                                   server_name, rbac_decision, confidence, target_n, total_pkts, feat, provided_gt=orig_req.ground_truth)
                    
                predictions[i] = {
                    "label": int(label),
                    "proba": [noise_prob, mcp_prob],
                    "rbac_decision": rbac_decision,
                    "rbac_reason": rbac_reason,
                    "server_name": server_name,
                    "role": role
                }
            except Exception as e:
                predictions[i] = {
                    "label": -1,
                    "proba": [0.0, 0.0],
                    "rbac_decision": "ERROR",
                    "rbac_reason": str(e)
                }
            
    return {"predictions": predictions}

@app.get("/api/flows")
def api_flows():
    return list(flow_log)

@app.get("/api/stats")
def api_stats():
    total = len(flow_log)
    decided = [f for f in flow_log if f["match"] is not None]
    correct = sum(1 for f in decided if f["match"])
    return {
        "total_flows": total,
        "accuracy": round(correct / len(decided) * 100, 1) if decided else 0,
        "mcp_count": sum(1 for f in flow_log if f["ground_truth"] == "MCP"),
        "normal_count": sum(1 for f in flow_log if f["ground_truth"] == "normal"),
        "unknown_count": sum(1 for f in flow_log if f["prediction"] == "Unknown_wait"),
    }

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def dashboard():
    return HTMLResponse(content=open("static/dashboard.html", "r", encoding="utf-8").read(), status_code=200)


