import pandas as pd
import numpy as np
import xgboost as xgb
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

THRESHOLDS = [3, 5, 8, 10, 15, 20]
MODEL_DIR = "models"
DATASET_PATH = "../dataset.csv"

def get_features_for_n(n):
    """Return the exact list of feature columns available at packet N."""
    features = ["entropy"]
    for i in range(n):
        features.append(f"seq_size_{i:02d}")
        features.append(f"seq_dir_{i:02d}")
        features.append(f"seq_iat_{i:02d}")
    return features

def train_early_classifiers():
    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at {DATASET_PATH}. Please run generate_dataset.sh first.")
        # Create a dummy dataset for testing the script if it doesn't exist
        print("Creating a dummy dataset to verify compilation...")
        df = pd.DataFrame(np.random.rand(100, 105), columns=[
            "duration_s", "total_pkts", "total_bytes", "pkts_up", "mean_pkt_sz",
            "std_pkt_sz", "min_pkt_sz", "max_pkt_sz", "mean_pkt_sz_up", "std_iat",
            "mean_iat_up", "std_iat_up", "std_iat_down", "byte_ratio_up", "pkt_ratio_up",
            "entropy"
        ] + [f"seq_size_{i:02d}" for i in range(20)] +
            [f"seq_dir_{i:02d}" for i in range(20)] +
            [f"seq_iat_{i:02d}" for i in range(20)] +
            [f"tls_up_{i:02d}" for i in range(3, 20)] +
            [f"tls_down_{i:02d}" for i in range(8, 20)])
        df["label"] = np.random.randint(0, 7, 100)
    else:
        df = pd.read_csv(DATASET_PATH)

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Label Map: 0=noise, 1=fetch, 2=memory, 3=filesystem, 4=github, 5=exa, 6=tavily
    y = df["label"].values

    for n in THRESHOLDS:
        print(f"\n--- Training Early Classifier N={n} ---")
        features = get_features_for_n(n)
        X = df[features].values

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = xgb.XGBClassifier(
            objective="multi:softprob",
            num_class=7,
            eval_metric="mlogloss",
            use_label_encoder=False,
            max_depth=5,
            learning_rate=0.1,
            n_estimators=100
        )

        model.fit(X_train, y_train)

        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        print(f"Accuracy at N={n}: {acc*100:.2f}%")
        
        model_path = os.path.join(MODEL_DIR, f"xgb_n{n}.json")
        model.save_model(model_path)
        print(f"Saved model to {model_path}")

    # Train Full Flow Classifier
    print(f"\n--- Training Full Flow Classifier ---")
    all_features = [c for c in df.columns if c not in ["flow_display", "label"]]
    X = df[all_features].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = xgb.XGBClassifier(objective="multi:softprob", num_class=7)
    model.fit(X_train, y_train)
    acc = accuracy_score(y_test, model.predict(X_test))
    print(f"Full Classifier Accuracy: {acc*100:.2f}%")
    model.save_model(os.path.join(MODEL_DIR, "xgb_full.json"))

if __name__ == "__main__":
    train_early_classifiers()
