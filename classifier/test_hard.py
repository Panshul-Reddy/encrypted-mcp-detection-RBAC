import pandas as pd
import numpy as np
import joblib
import os
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, classification_report
import warnings
warnings.filterwarnings('ignore') # Ignore feature names mismatch warnings if any

DATASET_PATH = "dataset_hard.csv"
MODEL_DIR = "classifier/models"
THRESHOLDS = [3, 5, 8, 10, 15, 20]

def get_features_for_n(n):
    features = [
        "duration_s", "total_pkts", "total_bytes", "pkts_up",
        "mean_pkt_sz", "std_pkt_sz", "min_pkt_sz", "max_pkt_sz",
        "mean_pkt_sz_up", "std_iat", "mean_iat_up",
        "std_iat_up", "std_iat_down", "byte_ratio_up", "pkt_ratio_up",
    ]
    for i in range(n):
        features.append(f"seq_size_{i:02d}")
        features.append(f"seq_dir_{i:02d}")
        features.append(f"seq_iat_{i:02d}")
    return features

def get_snapshot(df, n):
    temp = df[df["total_pkts"] <= n]
    return temp.sort_values("total_pkts").groupby(["flow_display", "start_ts"]).last().reset_index()

def evaluate():
    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at {DATASET_PATH}")
        exit(1)

    print("Loading hard negative dataset...")
    df = pd.read_csv(DATASET_PATH)
    
    print(f"\nDataset shape: {df.shape}")
    print("Label distribution (0=Noise, 1-6=MCP):")
    print(df["label"].value_counts().sort_index().to_string())

    for n in THRESHOLDS:
        model_path = os.path.join(MODEL_DIR, f"n{n}.joblib")
        if not os.path.exists(model_path):
            continue
            
        print(f"\n{'='*50}\nEvaluating N={n} Model against Hard Negatives\n{'='*50}")
        model = joblib.load(model_path)
        
        # Get data snapshot for N
        df_n = get_snapshot(df, n)
        features = get_features_for_n(n)
        
        # Ensure only existing features are used
        features = [f for f in features if f in df_n.columns]
        
        X = df_n[features].values
        y_true_multi = df_n["label"].values
        y_true_bin = (y_true_multi > 0).astype(int)
        
        preds_multi = model.predict(X)
        preds_bin = (preds_multi > 0).astype(int)
        
        acc_bin = accuracy_score(y_true_bin, preds_bin)
        f1_bin = f1_score(y_true_bin, preds_bin, average="binary")
        
        print(f"Binary Test Accuracy at N={n}: {acc_bin*100:.2f}%")
        print(f"Binary Test F1 (MCP=1):     {f1_bin*100:.2f}%")
        
        print("\nConfusion Matrix (Binary: 0=Noise, 1=MCP):")
        cm = confusion_matrix(y_true_bin, preds_bin, labels=[0, 1])
        print(cm)
        
        false_positives = cm[0][1]
        false_negatives = cm[1][0]
        print(f"\nFalse Positives (Noise incorrectly marked as MCP): {false_positives}")
        print(f"False Negatives (MCP incorrectly marked as Noise): {false_negatives}")

if __name__ == "__main__":
    evaluate()
