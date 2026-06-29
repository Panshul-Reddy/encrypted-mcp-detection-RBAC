import os
import pandas as pd
import numpy as np
from pathlib import Path

reports_dir = "classifier/models/reports"

print("=" * 80)
print("MODEL PERFORMANCE ANALYSIS")
print("=" * 80)

# Find all confusion matrix files
cm_files = sorted(Path(reports_dir).glob("*_confusion_matrix.csv"))
results = []

for cm_path in cm_files:
    threshold = cm_path.stem.replace("_confusion_matrix", "")
    cm_file = str(cm_path)
    feat_file = os.path.join(reports_dir, f"{threshold}_feature_importance.csv")
    
    if not os.path.exists(cm_file):
        continue
    
    cm = pd.read_csv(cm_file, index_col=0)
    accuracy = np.trace(cm.values) / cm.values.sum()
    
    feat_df = pd.read_csv(feat_file)
    top_3_features = feat_df.head(3)['feature'].tolist()
    
    results.append({
        'threshold': f"N={threshold}",
        'accuracy': accuracy * 100,
        'top_features': ', '.join(top_3_features)
    })
    
    print(f"\n{'='*80}")
    print(f"Threshold: N={threshold}")
    print(f"{'='*80}")
    print(f"Accuracy: {accuracy*100:.2f}%")
    print(f"\nTop 3 Features:")
    for i, feat in enumerate(top_3_features, 1):
        print(f"  {i}. {feat}")
    
    print(f"\nConfusion Matrix:")
    print(cm)

print(f"\n{'='*80}")
print("SUMMARY - ACCURACY BY THRESHOLD")
print(f"{'='*80}")
for r in results:
    print(f"{r['threshold']:12s}: {r['accuracy']:6.2f}%")

best = max(results, key=lambda x: x['accuracy'])
print(f"\n{'='*80}")
print(f"BEST PERFORMING THRESHOLD: {best['threshold']} with {best['accuracy']:.2f}% accuracy")
print(f"Top Features: {best['top_features']}")
print(f"{'='*80}")
