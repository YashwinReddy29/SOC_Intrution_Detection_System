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
    """Production-oriented wrapper around an Isolation Forest artifact."""

    VERSION = "2.0.0"

    def __init__(self, artifact_path: str = "ml/models/isolation_forest.joblib"):
        self.artifact_path = Path(artifact_path)
        self.model: Optional[IsolationForest] = None
        self.threshold: float = 0.0
        self.feature_columns = FEATURE_COLUMNS.copy()

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

    def anomaly_scores(self, features: pd.DataFrame) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model has not been trained or loaded")
        X = features[self.feature_columns].astype(float)
        # Isolation Forest: lower decision_function means more anomalous.
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
                "version": self.VERSION,
            },
            self.artifact_path,
        )

    def load(self) -> None:
        artifact = joblib.load(self.artifact_path)
        self.model = artifact["model"]
        self.threshold = float(artifact["threshold"])
        self.feature_columns = artifact["feature_columns"]
