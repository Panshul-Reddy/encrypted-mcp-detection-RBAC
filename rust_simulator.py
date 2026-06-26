import os
import sys
import time
import random
import json
import urllib.request
import pandas as pd
import numpy as np

API_URL = "http://localhost:5050/predict"

def get_features_for_n(n):
    features = ["entropy"]
    for i in range(n):
        features.append(f"seq_size_{i:02d}")
        features.append(f"seq_dir_{i:02d}")
        features.append(f"seq_iat_{i:02d}")
    return features

def simulate_traffic():
    print("[Simulator] Starting simulated traffic generation...")
    
    # Load dataset
    for p in ["classifier/dataset.csv", "dataset.csv", "../dataset.csv"]:
        if os.path.exists(p):
            df = pd.read_csv(p)
            break
    else:
        print("[Simulator] Error: dataset.csv not found")
        return

    # Simulate 3 different clients
    clients = [
        {"ip": "10.11.0.30", "role": "full"},
        {"ip": "10.11.0.40", "role": "readonly"},
        {"ip": "192.168.1.99", "role": "unknown"}
    ]
    
    thresholds = [3, 5, 8, 10, 15, 20]
    
    while True:
        try:
            client = random.choice(clients)
            
            # 80% chance of MCP traffic, 20% noise
            if random.random() < 0.2:
                target_label = 0
            else:
                target_label = random.choice([1, 2, 3, 4, 5, 6])
                
            label_df = df[df["label"] == target_label]
            if len(label_df) == 0:
                continue
                
            sample = label_df.sample(1).iloc[0]
            
            # Pick a random threshold
            n = random.choice(thresholds)
            
            # Prepare full 105 feature array (zeroed out)
            x_full = [0.0] * 105
            
            # Map features up to N
            feature_cols = get_features_for_n(n)
            
            # FastFlow expects:
            # 15 = entropy
            # 16-35 = sizes
            # 36-55 = dirs
            # 56-75 = iats
            
            if "entropy" in sample:
                x_full[15] = float(sample["entropy"])
                
            for i in range(n):
                if f"seq_size_{i:02d}" in sample:
                    x_full[16 + i] = float(sample[f"seq_size_{i:02d}"])
                if f"seq_dir_{i:02d}" in sample:
                    x_full[36 + i] = float(sample[f"seq_dir_{i:02d}"])
                if f"seq_iat_{i:02d}" in sample:
                    x_full[56 + i] = float(sample[f"seq_iat_{i:02d}"])
            
            payload = {
                "features": x_full,
                "n_packets": n,
                "source_ip": client["ip"]
            }
            
            req = urllib.request.Request(API_URL, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=2)
            
            # Sleep a bit to make it look like real streaming traffic
            time.sleep(random.uniform(0.5, 2.0))
            
        except Exception as e:
            # API might not be ready yet
            time.sleep(1)

if __name__ == "__main__":
    try:
        simulate_traffic()
    except KeyboardInterrupt:
        pass
