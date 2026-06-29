import pandas as pd
import numpy as np
import joblib
import os
from time import perf_counter
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, classification_report
from sklearn.inspection import permutation_importance
from sklearn.ensemble import ExtraTreesClassifier

THRESHOLDS = [3, 5, 8, 10, 15, 20]
MODEL_DIR = "models"
REPORT_DIR = os.path.join(MODEL_DIR, "reports")
DATASET_PATH = "../dataset.csv"


def get_features_for_n(n):
    """Return the exact list of feature columns available at packet N.

    Note: 'entropy' has been removed (near-constant ~5.6 bits on TLS ciphertext,
    no discriminating signal across any label class).
    """
    features = [
        "duration_s",
        "total_pkts",
        "total_bytes",
        "pkts_up",
        "mean_pkt_sz",
        "std_pkt_sz",
        "min_pkt_sz",
        "max_pkt_sz",
        "mean_pkt_sz_up",
        "std_iat",
        "mean_iat_up",
        "std_iat_up",
        "std_iat_down",
        "byte_ratio_up",
        "pkt_ratio_up",
    ]
    for i in range(n):
        features.append(f"seq_size_{i:02d}")
        features.append(f"seq_dir_{i:02d}")
        features.append(f"seq_iat_{i:02d}")
    return features


def session_level_split(df, test_size=0.3, val_fraction=0.5, random_state=42):
    """Split by unique TCP sessions, not rows.

    Uses (flow_display, start_ts) as the session key. This is collision-free
    even with long captures where the OS may reuse ephemeral ports:
    - flow_display alone can collide when the OS reuses a src port for a new TCP
      connection within the same capture window (a real risk with 30-min captures
      cycling through ~28k ephemeral ports).
    - The previous key (flow_display + seq_iat_01 + seq_iat_02) used float IAT
      values that could theoretically collide for flows with similar timing.
    - start_ts is the PCAP timestamp of the first packet — microsecond resolution,
      unique per TCP handshake by construction.

    Stratification is preserved using each session's label so class balance
    is maintained across all three splits.
    """
    df = df.copy()
    df["_session_key"] = (
        df["flow_display"].astype(str)
        + "||"
        + df["start_ts"].astype(str)
    )

    # One label per session (every row in a session shares the same label).
    session_df = df.groupby("_session_key")["label"].first().reset_index()
    unique_sessions = session_df["_session_key"].values
    session_labels = session_df["label"].values

    train_sessions, temp_sessions, _, temp_labels = train_test_split(
        unique_sessions,
        session_labels,
        test_size=test_size,
        random_state=random_state,
        stratify=session_labels,
    )
    val_sessions, test_sessions, _, _ = train_test_split(
        temp_sessions,
        temp_labels,
        test_size=val_fraction,
        random_state=random_state,
        stratify=temp_labels,
    )

    train_df = df[df["_session_key"].isin(train_sessions)].drop(columns=["_session_key"])
    val_df   = df[df["_session_key"].isin(val_sessions)].drop(columns=["_session_key"])
    test_df  = df[df["_session_key"].isin(test_sessions)].drop(columns=["_session_key"])
    return train_df, val_df, test_df


def build_model_candidates(random_state: int = 42):
    """Return a small set of strong tabular classifiers to compare on validation data."""
    candidates = {
        "extra_trees": ExtraTreesClassifier(
            n_estimators=400,
            random_state=random_state,
            n_jobs=-1,
            class_weight="balanced_subsample",
        ),
    }
    return candidates


def score_model(model, X, y):
    preds = model.predict(X)
    return {
        "accuracy": accuracy_score(y, preds),
        "macro_f1": f1_score(y, preds, average="macro"),
    }


def get_feature_importance(model, X_ref, y_ref):
    """Return a per-feature importance vector for any supported model."""
    if hasattr(model, "feature_importances_"):
        return np.asarray(model.feature_importances_, dtype=float)

    # Fallback for models without native importances.
    perm = permutation_importance(
        model,
        X_ref,
        y_ref,
        scoring="f1_macro",
        n_repeats=5,
        random_state=42,
        n_jobs=-1,
    )
    return np.asarray(perm.importances_mean, dtype=float)


def write_model_report(report_name, model_name, model, X_eval, y_eval, feature_names, labels=None):
    preds = model.predict(X_eval)
    if labels is None:
        labels = sorted(np.unique(np.concatenate([y_eval, preds])).tolist())

    cm = confusion_matrix(y_eval, preds, labels=labels)

    print(f"\nConfusion matrix for {report_name} ({model_name}):")
    print(cm)

    cm_path = os.path.join(REPORT_DIR, f"{report_name}_confusion_matrix.csv")
    cm_df = pd.DataFrame(
        cm,
        index=[f"true_{i}" for i in labels],
        columns=[f"pred_{i}" for i in labels],
    )
    cm_df.to_csv(cm_path, index=True)
    print(f"Saved confusion matrix to {cm_path}")

    importances = get_feature_importance(model, X_eval, y_eval)
    feat_df = pd.DataFrame(
        {
            "feature": feature_names,
            "importance": importances,
        }
    ).sort_values("importance", ascending=False)

    top_k = min(15, len(feat_df))
    print(f"Top {top_k} features for {report_name} ({model_name}):")
    for _, row in feat_df.head(top_k).iterrows():
        print(f"- {row['feature']}: {row['importance']:.6f}")

    feat_path = os.path.join(REPORT_DIR, f"{report_name}_feature_importance.csv")
    feat_df.to_csv(feat_path, index=False)
    print(f"Saved feature importance to {feat_path}")


def train_best_model(X_train, y_train, X_val, y_val):
    best_name = None
    best_model = None
    best_score = -1.0
    comparison_rows = []

    for name, model in build_model_candidates().items():
        print(f"Training candidate model: {name}")
        start_time = perf_counter()
        model.fit(X_train, y_train)
        fit_seconds = perf_counter() - start_time
        metrics = score_model(model, X_val, y_val)
        comparison_rows.append((name, fit_seconds, metrics["accuracy"], metrics["macro_f1"]))
        print(
            f"Validation metrics for {name}: "
            f"accuracy={metrics['accuracy'] * 100:.2f}%, "
            f"macro_f1={metrics['macro_f1'] * 100:.2f}%, "
            f"fit_time={fit_seconds:.2f}s"
        )
        if metrics["macro_f1"] > best_score:
            best_name = name
            best_model = model
            best_score = metrics["macro_f1"]

    print("\nComparison summary (validation set):")
    for name, fit_seconds, accuracy, macro_f1 in comparison_rows:
        print(
            f"- {name}: accuracy={accuracy * 100:.2f}%, "
            f"macro_f1={macro_f1 * 100:.2f}%, fit_time={fit_seconds:.2f}s"
        )

    return best_name, best_model, best_score


def train_early_classifiers():
    if not os.path.exists(DATASET_PATH):
        print(f"Dataset not found at {DATASET_PATH}. Please run generate_dataset.sh first.")
        exit(1)

    df = pd.read_csv(DATASET_PATH)

    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)

    # Sanity check: verify dataset has the expected columns.
    if "start_ts" not in df.columns:
        raise ValueError(
            "Dataset is missing 'start_ts' column. "
            "Re-run generate_dataset.sh to regenerate dataset.csv with the updated extractor."
        )
    if "entropy" in df.columns:
        print("WARNING: dataset has legacy 'entropy' column — it will be excluded from training.")

    print(f"\nDataset shape: {df.shape}")
    print("Label distribution:")
    print(df["label"].value_counts().sort_index().to_string())
    print(f"Noise share: {(df['label'] == 0).mean() * 100:.1f}%")
    print(f"MCP share:   {(df['label'] > 0).mean() * 100:.1f}%")

    # Session-level split — computed once and reused across all N thresholds and
    # both the multi-class and binary classifiers.
    train_df, val_df, test_df = session_level_split(df)
    
    def get_snapshot(split_df, n):
        temp = split_df[split_df["total_pkts"] <= n]
        return temp.sort_values("total_pkts").groupby(["flow_display", "start_ts"]).last().reset_index()
        
    def get_final_snapshot(split_df):
        return split_df[split_df["eval_n"] == "final"]

    # ── Multi-class early classifiers (N-packet thresholds) ──────────────────
    for n in THRESHOLDS:
        print(f"\n--- Training Early Classifier N={n} ---")
        features = get_features_for_n(n)

        # Guard: only keep features that actually exist in the dataset.
        features = [f for f in features if f in df.columns]
        
        train_n = get_snapshot(train_df, n)
        val_n = get_snapshot(val_df, n)
        test_n = get_snapshot(test_df, n)

        X_train = train_n[features].values
        y_train = train_n["label"].values
        X_val   = val_n[features].values
        y_val   = val_n["label"].values
        X_test  = test_n[features].values
        y_test  = test_n["label"].values

        model_name, model, _ = train_best_model(X_train, y_train, X_val, y_val)

        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        print(f"Selected model for N={n}: {model_name}")
        print(f"Multi-class Test Accuracy at N={n}: {acc*100:.2f}%")
        
        # Binary performance of this early model
        y_test_bin = (y_test > 0).astype(int)
        preds_bin = (preds > 0).astype(int)
        acc_bin = accuracy_score(y_test_bin, preds_bin)
        f1_bin = f1_score(y_test_bin, preds_bin, average="binary")
        print(f"Binary Test Accuracy at N={n}: {acc_bin*100:.2f}%")
        print(f"Binary Test F1 at N={n}: {f1_bin*100:.2f}%")

        model_path = os.path.join(MODEL_DIR, f"n{n}.joblib")
        joblib.dump(model, model_path)
        print(f"Saved model to {model_path}")

        write_model_report(
            report_name=f"n{n}",
            model_name=model_name,
            model=model,
            X_eval=X_test,
            y_eval=y_test,
            feature_names=features,
            labels=list(range(7)),
        )

    # ── Full flow multi-class classifier ─────────────────────────────────────
    print(f"\n--- Training Full Flow Classifier (multi-class, 7 labels) ---")
    non_feature_cols = {"flow_display", "label", "start_ts", "eval_n", "_session_key"}
    all_features = [c for c in df.columns if c not in non_feature_cols]
    
    train_final = get_final_snapshot(train_df)
    val_final = get_final_snapshot(val_df)
    test_final = get_final_snapshot(test_df)

    X_train = train_final[all_features].values
    y_train = train_final["label"].values
    X_val   = val_final[all_features].values
    y_val   = val_final["label"].values
    X_test  = test_final[all_features].values
    y_test  = test_final["label"].values

    model_name, model, _ = train_best_model(X_train, y_train, X_val, y_val)
    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"Selected model for full classifier: {model_name}")
    print(f"Full Classifier Accuracy (7-class): {acc*100:.2f}%")
    joblib.dump(model, os.path.join(MODEL_DIR, "full.joblib"))
    write_model_report(
        report_name="full",
        model_name=model_name,
        model=model,
        X_eval=X_test,
        y_eval=y_test,
        feature_names=all_features,
        labels=list(range(7)),
    )

    # ── Binary classifier: MCP (1) vs Noise (0) ──────────────────────────────
    # This is the primary security deliverable: detect any MCP traffic regardless
    # of which server is being contacted. The 7-class model tells you *which* server;
    # the binary model tells you *whether* it's MCP.
    print(f"\n--- Training Binary Classifier (MCP vs Noise) ---")

    train_bin = train_final.copy()
    train_bin["binary_label"] = (train_bin["label"] > 0).astype(int)
    val_bin = val_final.copy()
    val_bin["binary_label"] = (val_bin["label"] > 0).astype(int)
    test_bin = test_final.copy()
    test_bin["binary_label"] = (test_bin["label"] > 0).astype(int)

    X_train_b = train_bin[all_features].values
    y_train_b = train_bin["binary_label"].values
    X_val_b   = val_bin[all_features].values
    y_val_b   = val_bin["binary_label"].values
    X_test_b  = test_bin[all_features].values
    y_test_b  = test_bin["binary_label"].values

    binary_model = ExtraTreesClassifier(
        n_estimators=400,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    t0 = perf_counter()
    binary_model.fit(X_train_b, y_train_b)
    fit_secs = perf_counter() - t0

    preds_b = binary_model.predict(X_test_b)
    acc_b = accuracy_score(y_test_b, preds_b)
    f1_b  = f1_score(y_test_b, preds_b, average="binary")
    print(f"Binary Classifier — fit_time={fit_secs:.2f}s")
    print(f"Binary Test Accuracy: {acc_b*100:.2f}%")
    print(f"Binary Test F1 (MCP=positive): {f1_b*100:.2f}%")
    print("\nClassification report (binary):")
    print(classification_report(y_test_b, preds_b, target_names=["noise", "MCP"]))

    joblib.dump(binary_model, os.path.join(MODEL_DIR, "binary.joblib"))
    print(f"Saved binary model to {os.path.join(MODEL_DIR, 'binary.joblib')}")

    write_model_report(
        report_name="binary",
        model_name="extra_trees_binary",
        model=binary_model,
        X_eval=X_test_b,
        y_eval=y_test_b,
        feature_names=all_features,
        labels=[0, 1],
    )


if __name__ == "__main__":
    train_early_classifiers()
