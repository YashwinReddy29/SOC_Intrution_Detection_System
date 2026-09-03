"""Event-driven ML ingestion and real-time Socket.IO alerts."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from app.models.database import insert_log
from app.services.threat_service import threat_score
from app import socketio
from app.security import valid_api_key

from ml.detection_service import DetectionService


ml_bp = Blueprint("ml", __name__, url_prefix="/api/ml")

# Load the persisted model once when the application imports this controller.
ARTIFACT_PATH = "ml/models/isolation_forest.joblib"
detector = DetectionService(ARTIFACT_PATH)


@ml_bp.route("/health", methods=["GET"])
def ml_health():
    """Return detector readiness and model metadata."""
    return jsonify(
        {
            "status": "ready",
            "model_version": detector.model.VERSION,
            "threshold": detector.model.threshold,
            "features": detector.model.feature_columns,
        }
    )


@ml_bp.route("/events", methods=["POST"])
def ingest_event():
    """Score one SOC event and emit the result immediately."""
    expected_key = current_app.config.get("ML_API_KEY")
    if not valid_api_key(request.headers.get("X-API-Key"), expected_key):
        return jsonify({"error": "Unauthorized"}), 401

    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    try:
        result = detector.analyze(event)
    except (ValueError, TypeError, KeyError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Detection service failure"}), 500

    ip = str(event["source_ip"])
    try:
        threat = int(threat_score(ip))
    except Exception:
        threat = 0

    message = (
        f"ML {result.severity}: anomaly={result.anomaly_score:.4f} "
        f"risk={result.risk_score:.1f} source={ip}"
    )
    insert_log(message, int(round(result.risk_score)), threat)

    payload = {
        "event": event,
        "detection": result.to_dict(),
        "model_version": detector.model.VERSION,
        "threshold": detector.model.threshold,
    }

    # Emit after scoring and persistence so connected dashboards receive the
    # same result returned to the event producer.
    socketio.emit("detection_event", payload)

    if result.detected:
        socketio.emit(
            "new_alert",
            {
                "message": message,
                "severity": result.severity,
                "risk_score": result.risk_score,
                "source_ip": ip,
                "latency_ms": result.latency_ms,
            },
        )

    return jsonify(payload), 200
