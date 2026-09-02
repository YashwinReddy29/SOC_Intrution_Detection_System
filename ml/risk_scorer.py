"""Risk scoring for ML-generated SOC detections."""

from __future__ import annotations


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, float(value)))


def score_risk(anomaly_score: float, features: dict) -> dict:
    """Convert anomaly and behavioral signals into a bounded SOC risk score."""
    anomaly_component = _clamp((anomaly_score + 0.05) / 0.15 * 100.0)
    failed_component = _clamp(float(features.get("failed_login_rate", 0.0)) * 100.0)
    port_component = _clamp(float(features.get("port_diversity", 0.0)) * 100.0)
    geo_component = _clamp(float(features.get("geographic_distance", 0.0)) / 5000.0 * 100.0)
    exfil_component = _clamp(max(0.0, float(features.get("bytes_in_out_ratio", 0.0))) * 20.0)

    risk = (
        0.55 * anomaly_component
        + 0.20 * failed_component
        + 0.10 * port_component
        + 0.10 * geo_component
        + 0.05 * exfil_component
    )
    risk = round(_clamp(risk), 2)

    if risk >= 85:
        severity = "CRITICAL"
    elif risk >= 65:
        severity = "HIGH"
    elif risk >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {"risk_score": risk, "severity": severity}
