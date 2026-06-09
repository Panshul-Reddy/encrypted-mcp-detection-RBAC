"""
Inference server — loads the trained MCP classifier and serves predictions
over HTTP.

Endpoints:
    POST /predict       — classify a single feature vector
    POST /predict_batch — classify a batch of feature vectors
    GET  /health        — readiness check

Usage:
    python inference_server.py
    python inference_server.py --model ../models/mcp_classifier.pkl --port 5000
"""

import argparse
import os
import time

import joblib
import numpy as np
from flask import Flask, jsonify, request

app = Flask(__name__)


model = None
feature_cols = None


def load_model(model_path: str, features_path: str):
    global model, feature_cols
    print(f"Loading model from {model_path}")
    model = joblib.load(model_path)
    print(f"  Model type: {type(model).__name__}")
    if hasattr(model, "classes_"):
        print(f"  Classes: {model.classes_}")
    if hasattr(model, "n_estimators"):
        print(f"  Estimators: {model.n_estimators}")

    print(f"Loading feature columns from {features_path}")
    feature_cols = joblib.load(features_path)
    print(f"  Features: {len(feature_cols)}")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})


@app.route("/predict", methods=["POST"])
def predict():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 503

    data = request.get_json()
    if data is None or "features" not in data:
        return jsonify({"error": "Missing 'features' in request body"}), 400

    features = np.array(data["features"], dtype=np.float64).reshape(1, -1)

    if features.shape[1] != len(feature_cols):
        return jsonify({
            "error": f"Expected {len(feature_cols)} features, got {features.shape[1]}"
        }), 400

    start = time.perf_counter()
    label = int(model.predict(features)[0])
    proba = model.predict_proba(features)[0].tolist()
    elapsed_ms = (time.perf_counter() - start) * 1000

    return jsonify({
        "label": label,
        "proba": proba,
        "inference_ms": round(elapsed_ms, 3),
    })


@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    if model is None:
        return jsonify({"error": "Model not loaded"}), 503

    data = request.get_json()
    if data is None or "batch" not in data:
        return jsonify({"error": "Missing 'batch' in request body"}), 400

    batch = np.array(data["batch"], dtype=np.float64)

    if batch.ndim != 2 or batch.shape[1] != len(feature_cols):
        return jsonify({
            "error": f"Expected Nx{len(feature_cols)} array, got {batch.shape}"
        }), 400

    start = time.perf_counter()
    labels = model.predict(batch).astype(int).tolist()
    probas = model.predict_proba(batch).tolist()
    elapsed_ms = (time.perf_counter() - start) * 1000

    predictions = [
        {"label": label, "proba": proba}
        for label, proba in zip(labels, probas)
    ]

    return jsonify({
        "predictions": predictions,
        "inference_ms": round(elapsed_ms, 3),
        "batch_size": len(labels),
    })


def main():
    parser = argparse.ArgumentParser(description="MCP classifier inference server")
    parser.add_argument(
        "--model",
        default=os.getenv("MODEL_PATH", "../models/mcp_classifier.pkl"),
        help="Path to trained model (default: ../models/mcp_classifier.pkl)",
    )
    parser.add_argument(
        "--features",
        default=os.getenv("FEATURES_PATH", "../models/feature_cols.pkl"),
        help="Path to feature columns (default: ../models/feature_cols.pkl)",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("HOST", "0.0.0.0"),
        help="Bind host (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", "5000")),
        help="Bind port (default: 5000)",
    )
    args = parser.parse_args()

    load_model(args.model, args.features)

    print(f"\nStarting inference server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
