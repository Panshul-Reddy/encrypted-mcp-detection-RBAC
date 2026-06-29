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
import time

app = FastAPI(title="FastFlow Early Inference API")

THRESHOLDS = [3, 5, 8, 10, 15, 20]
models = {}


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

class PredictBatchRequest(BaseModel):
    features_batch: list[list[float]]

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
            
    if target_n is None:
        return {"label": 0, "proba": [1.0, 0.0]} # Default noise for early packets
            
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
    
    # Progressive Confidence Thresholding
    if target_n != "full" and target_n < 20:
        if max(probas) < 0.85:
            # Fallback strategy: wait for higher confidence before returning a definitive prediction.
            pass

    return {
        "label": label,
        "proba": [noise_prob, mcp_prob]
    }

@app.post("/predict_batch")
def predict_batch(req: PredictBatchRequest):
    predictions = [None] * len(req.features_batch)
    groups = {}
    
    for idx, feat in enumerate(req.features_batch):
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
            predictions[idx] = {"label": 0, "proba": [1.0, 0.0]}
            continue
            
        groups.setdefault(target_n, []).append((idx, feat))
        
    for target_n, items in groups.items():
        indices = [item[0] for item in items]
        feats = [item[1] for item in items]
        
        model = models[target_n]
        if target_n != "full":
            feat_indices = get_feature_indices(target_n)
            x = np.array([[f[i] for i in feat_indices] for f in feats])
        else:
            x = np.array(feats)
            
        probas_batch = model.predict_proba(x)
        
        for i, probas in zip(indices, probas_batch):
            noise_prob = float(probas[0])
            mcp_prob = float(sum(probas[1:]))
            
            if mcp_prob > noise_prob:
                label = int(np.argmax(probas[1:]) + 1)
            else:
                label = 0
                
            predictions[i] = {
                "label": int(label),
                "proba": [noise_prob, mcp_prob]
            }
            
    return {"predictions": predictions}
