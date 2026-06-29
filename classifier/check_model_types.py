import joblib
import os

models_dir = "models"
thresholds = [3, 5, 8, 10, 15, 20, "full"]

print("=" * 80)
print("SELECTED MODEL TYPES PER THRESHOLD")
print("=" * 80)

for threshold in thresholds:
    model_path = os.path.join(models_dir, f"n{threshold}.joblib" if threshold != "full" else "full.joblib")
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        model_type = type(model).__name__
        print(f"N={str(threshold):6s}: {model_type}")
