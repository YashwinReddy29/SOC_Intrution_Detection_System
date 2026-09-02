"""Run the v2 SOC ML experiment end-to-end.

Usage:
    python scripts/run_ml_experiment.py
"""

from pathlib import Path
import json

import pandas as pd
from sklearn.model_selection import train_test_split

from ml.eval_metrics import benchmark_scorer, evaluate, save_metrics, tune_threshold
from ml.feature_extractor import RollingFeatureExtractor
from ml.ml_service import MLService
from ml.synthetic_data_generator import GeneratorConfig, generate_dataset, save_dataset


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "ml" / "data" / "soc_events_v2.csv"
MODEL_PATH = ROOT / "ml" / "models" / "isolation_forest.joblib"
REPORT_PATH = ROOT / "ml" / "reports" / "ml_metrics_v2.json"


def main():
    print("[1/6] Generating 10,000 realistic temporal SOC events...")
    df = generate_dataset(GeneratorConfig(total_events=10_000, attack_fraction=0.20, seed=42))
    save_dataset(df, str(DATA_PATH))
    print(df["label"].value_counts().sort_index().to_dict())

    print("[2/6] Building rolling behavioral features...")
    extractor = RollingFeatureExtractor(window_seconds=300)
    normal_for_stats = df.loc[df["label"] == 0, "timestamp"]
    extractor.fit_time_statistics(normal_for_stats)
    features = extractor.transform(df)
    labels = df["label"].astype(int).reset_index(drop=True)

    print("[3/6] Creating train/validation/test splits...")
    # Split by event after feature construction; model training remains normal-only.
    X_train, X_temp, y_train, y_temp = train_test_split(
        features, labels, test_size=0.30, stratify=labels, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=43
    )

    print("[4/6] Training Isolation Forest on NORMAL training traffic only...")
    service = MLService(str(MODEL_PATH))
    train_info = service.train(X_train, y_train)

    val_scores = service.anomaly_scores(X_val)
    selected, target_met = tune_threshold(y_val, val_scores, min_precision=0.89)
    service.set_threshold(selected["threshold"])

    print("Validation operating point:")
    print(json.dumps(selected, indent=2))
    print(f"89% precision target met: {target_met}")

    print("[5/6] Evaluating untouched test set...")
    test_scores = service.anomaly_scores(X_test)
    test_predictions = (test_scores >= service.threshold).astype(int)
    latencies = benchmark_scorer(service, X_test)
    metrics = evaluate(
        y_test,
        test_predictions,
        latencies_ms=latencies,
        threshold=service.threshold,
    )
    metrics.update({
        "dataset_size": int(len(df)),
        "attack_count": int(labels.sum()),
        "normal_count": int((labels == 0).sum()),
        "training_samples": train_info["training_samples"],
        "validation_precision": selected["precision"],
        "validation_recall": selected["recall"],
        "validation_f1": selected["f1"],
        "precision_target_met_on_validation": target_met,
        "model_version": service.VERSION,
    })

    service.save()
    save_metrics(metrics, str(REPORT_PATH))

    print("[6/6] Final TEST metrics")
    print(json.dumps(metrics, indent=2))
    print(f"\nSaved dataset: {DATA_PATH}")
    print(f"Saved model:   {MODEL_PATH}")
    print(f"Saved report:  {REPORT_PATH}")


if __name__ == "__main__":
    main()
