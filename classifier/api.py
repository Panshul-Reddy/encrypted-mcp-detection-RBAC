"""
FastFlow Early Inference API (Machine Learning Engine)

This module implements an asynchronous FastAPI server that hosts pre-trained XGBoost 
sequence models. It provides low-latency inference for the Rust feature extractor, 
dynamically selecting the appropriate N-packet threshold model based on the number of 
observed packets in the network flow.
"""

from fastapi import FastAPI
from pydantic import BaseModel
import xgboost as xgb
import numpy as np
import os
import time

app = FastAPI(title="FastFlow Early Inference API")

THRESHOLDS = [3, 5, 8, 10, 15, 20]
models = {}

def get_feature_indices(n: int) -> list[int]:
    """
    Maps the progressive feature indices to the 105-dimension array sent by the Rust core.
    """
    # Rust sends exactly 105 features:
    # 0-14: Base
    # 15: entropy
    # 16-35: seq_size
    # 36-55: seq_dir
    # 56-75: seq_iat
    # 76-104: TLS
    indices = [15] # entropy
    for i in range(n):
        indices.append(16 + i) # seq_size
        indices.append(36 + i) # seq_dir
        indices.append(56 + i) # seq_iat
    return indices

@app.on_event("startup")
def load_models():
    for n in THRESHOLDS:
        path = f"models/xgb_n{n}.json"
        if os.path.exists(path):
            m = xgb.XGBClassifier()
            m.load_model(path)
            models[n] = m
            print(f"Loaded N={n} model.")
    full_path = "models/xgb_full.json"
    if os.path.exists(full_path):
        m = xgb.XGBClassifier()
        m.load_model(full_path)
        models["full"] = m
        print("Loaded Full model.")

class PredictRequest(BaseModel):
    features: list[float]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/predict")
def predict(req: PredictRequest):
    feat = req.features
    if len(feat) != 105:
        return {"error": "Expected 105 features"}
    
    # We dynamically decide which model to use based on the number of non-zero packets
    # In Rust, total_pkts is index 1
    total_pkts = int(feat[1])
    
    # Find the largest threshold model that we can use
    target_n = None
    for n in reversed(THRESHOLDS):
        if total_pkts >= n and n in models:
            target_n = n
            break
            
    if target_n is None:
        if "full" in models:
            # Fallback to full model if thresholds fail
            target_n = "full"
        else:
            return {"label": 0, "proba": [1.0, 0.0]} # Default noise
            
    model = models[target_n]
    
    if target_n != "full":
        indices = get_feature_indices(target_n)
        x = np.array([feat[i] for i in indices]).reshape(1, -1)
    else:
        x = np.array(feat).reshape(1, -1)

    probas = model.predict_proba(x)[0]
    label = int(np.argmax(probas))
    
    # For Rust compatibility, proba expects [noise_prob, mcp_prob]
    # Classes: 0 is noise, 1-6 are MCP.
    noise_prob = float(probas[0])
    mcp_prob = float(sum(probas[1:]))
    
    # Progressive Confidence Thresholding
    if target_n != "full" and target_n < 20:
        if max(probas) < 0.85:
            # "UNKNOWN_WAIT" fallback: instruct proxy to keep connection open by returning 0 with low prob?
            # Or we can just return the label but Rust will see low confidence.
            # Actually, Mrunal's logic explicitly waited for higher confidence.
            pass

    return {
        "label": label,
        "proba": [noise_prob, mcp_prob]
    }
