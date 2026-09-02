"""Real-time event detection service combining rolling features and ML scoring."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter

import pandas as pd

from ml.feature_extractor import FEATURE_COLUMNS, RollingFeatureExtractor
from ml.ml_service import MLService
from ml.risk_scorer import score_risk


@dataclass
class DetectionResult:
    detected: bool
    anomaly_score: float
    risk_score: float
    severity: str
    latency_ms: float
    features: dict
    feature_columns: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class DetectionService:
    """Long-lived detector for event-driven inference.

    The same rolling feature state is retained between events, while the model
    artifact is loaded once at application startup.
    """

    VERSION = "2.1.0"

    def __init__(self, artifact_path: str = "ml/models/isolation_forest.joblib"):
        self.model = MLService(artifact_path)
        self.model.load()

        stats = self.model.feature_stats
        self.extractor = RollingFeatureExtractor(window_seconds=300)
        self.extractor.time_mean = float(stats.get("time_mean", 12.0))
        self.extractor.time_std = float(stats.get("time_std", 4.0)) or 1.0

    @staticmethod
    def validate_event(event: dict) -> None:
        required = {
            "timestamp",
            "source_ip",
            "destination_port",
            "protocol",
            "bytes_in",
            "bytes_out",
            "failed_logins",
            "latitude",
            "longitude",
        }
        missing = sorted(required - set(event))
        if missing:
            raise ValueError(f"Missing required event fields: {', '.join(missing)}")

    def analyze(self, event: dict) -> DetectionResult:
        start = perf_counter()
        self.validate_event(event)

        features = self.extractor.transform_event(event)
        frame = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        scores, predictions = self.model.predict_scores(frame)

        anomaly_score = float(scores[0])
        detected = bool(predictions[0])
        risk = score_risk(anomaly_score, features)

        latency_ms = (perf_counter() - start) * 1000.0

        return DetectionResult(
            detected=detected,
            anomaly_score=round(anomaly_score, 6),
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            latency_ms=round(latency_ms, 4),
            features=features,
            feature_columns=FEATURE_COLUMNS.copy(),
        )
