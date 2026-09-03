"""Isolation Forest training, scoring, threshold selection, and persistence."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ml.feature_extractor import FEATURE_COLUMNS


class MLService:
    """Production-oriented wrapper around a persisted Isolation Forest."""

    VERSION = "2.1.0"

    def __init__(self, artifact_path: str = "ml/models/isolation_forest.joblib"):
        self.artifact_path = Path(artifact_path)
        self.model: Optional[IsolationForest] = None
        self.threshold: float = 0.0
        self.feature_columns = FEATURE_COLUMNS.copy()
        self.feature_stats = {"time_mean": 12.0, "time_std": 4.0}

    def train(self, features: pd.DataFrame, labels: Optional[pd.Series] = None) -> dict:
        """Train only on normal examples and return training metadata."""
        X = features[self.feature_columns].astype(float)
        if labels is not None:
            normal_mask = np.asarray(labels) == 0
            X = X.loc[normal_mask]

        if len(X) < 100:
            raise ValueError("At least 100 normal training samples are required")

        self.model = IsolationForest(
            n_estimators=400,
            max_samples="auto",
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)

        return {
            "version": self.VERSION,
            "training_samples": int(len(X)),
            "features": self.feature_columns,
        }

    def set_feature_stats(self, time_mean: float, time_std: float) -> None:
        """Persist training-time statistics required by live feature extraction."""
        self.feature_stats = {
            "time_mean": float(time_mean),
            "time_std": float(time_std) if float(time_std) > 0 else 1.0,
        }

    def anomaly_scores(self, features: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model has not been trained or loaded")
        X = features[self.feature_columns].astype(float)
        return -self.model.decision_function(X)

    def set_threshold(self, threshold: float) -> None:
        self.threshold = float(threshold)

    def predict_scores(self, features: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        scores = self.anomaly_scores(features)
        predictions = (scores >= self.threshold).astype(int)
        return scores, predictions

    def save(self) -> None:
        if self.model is None:
            raise RuntimeError("Cannot save an untrained model")
        self.artifact_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "threshold": self.threshold,
                "feature_columns": self.feature_columns,
                "feature_stats": self.feature_stats,
                "version": self.VERSION,
            },
            self.artifact_path,
        )

    def load(self) -> None:
        if not self.artifact_path.exists():
            raise FileNotFoundError(f"Model artifact not found: {self.artifact_path}")

        artifact = joblib.load(self.artifact_path)
        self.model = artifact["model"]
        self.threshold = float(artifact["threshold"])
        self.feature_columns = artifact.get("feature_columns", FEATURE_COLUMNS.copy())
        self.feature_stats = artifact.get(
            "feature_stats",
            {"time_mean": 12.0, "time_std": 4.0},
        )
