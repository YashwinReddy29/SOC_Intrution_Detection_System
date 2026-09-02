"""Evaluation and threshold tuning utilities."""

from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


def tune_threshold(y_true, scores, min_precision: float = 0.89):
    """Select the threshold with maximum recall while satisfying precision target.

    If the target precision is unattainable, return the threshold with maximum F1.
    This fallback is intentionally reported so the experiment never fabricates a
    target result.
    """
    y_true = np.asarray(y_true)
    scores = np.asarray(scores)
    thresholds = np.unique(np.quantile(scores, np.linspace(0.50, 0.999, 1000)))

    candidates = []
    all_candidates = []
    for threshold in thresholds:
        pred = (scores >= threshold).astype(int)
        precision = precision_score(y_true, pred, zero_division=0)
        recall = recall_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        result = {
            "threshold": float(threshold),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        }
        all_candidates.append(result)
        if precision >= min_precision:
            candidates.append(result)

    if candidates:
        return max(candidates, key=lambda x: (x["recall"], x["f1"])), True
    return max(all_candidates, key=lambda x: x["f1"]), False


def evaluate(y_true, predictions, latencies_ms=None, threshold=None):
    y_true = np.asarray(y_true)
    predictions = np.asarray(predictions)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    result = {
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
    if threshold is not None:
        result["threshold"] = float(threshold)
    if latencies_ms is not None and len(latencies_ms):
        result.update({
            "latency_ms_mean": float(np.mean(latencies_ms)),
            "latency_ms_p50": float(np.percentile(latencies_ms, 50)),
            "latency_ms_p95": float(np.percentile(latencies_ms, 95)),
            "latency_ms_p99": float(np.percentile(latencies_ms, 99)),
        })
    return result


def benchmark_scorer(model, features):
    """Measure model scoring latency independently of dataset generation."""
    latencies = []
    for i in range(len(features)):
        row = features.iloc[[i]]
        start = perf_counter()
        model.anomaly_scores(row)
        latencies.append((perf_counter() - start) * 1000.0)
    return np.asarray(latencies)


def save_metrics(metrics: dict, path: str):
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
