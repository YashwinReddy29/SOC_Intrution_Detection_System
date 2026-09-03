import json
import logging
import os
import time
import uuid

from flask import Flask, g, jsonify, request
from flask_socketio import SocketIO

from app.security import InMemoryRateLimiter

socketio = SocketIO(
    cors_allowed_origins=os.getenv("SOCKETIO_CORS_ORIGINS", "*").split(","),
    async_mode="gevent",
)
logger = logging.getLogger("soc")


def create_app():
    """Create the Flask application with event-driven ML detection."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "development-only-change-me")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.config["ML_API_KEY"] = os.getenv("ML_API_KEY")
    app.config["ML_RATE_LIMIT"] = int(os.getenv("ML_RATE_LIMIT", "300"))

    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(message)s")
    ml_rate_limiter = InMemoryRateLimiter(limit=app.config["ML_RATE_LIMIT"], window_seconds=60)

    @app.before_request
    def attach_request_context():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.request_started = time.perf_counter()

        if request.path == "/api/ml/events":
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
            if not ml_rate_limiter.allow(client_ip):
                retry_after = ml_rate_limiter.retry_after(client_ip)
                response = jsonify({
                    "error": "Rate limit exceeded",
                    "retry_after_seconds": retry_after,
                    "request_id": g.request_id,
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response

    @app.after_request
    def add_security_headers(response):
        request_id = getattr(g, "request_id", "unknown")
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        duration_ms = (
            time.perf_counter()
            - getattr(g, "request_started", time.perf_counter())
        ) * 1000.0
        logger.info(json.dumps({
            "request_id": request_id,
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "duration_ms": round(duration_ms, 3),
        }))
        return response

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify({
            "error": "Request payload exceeds the 64 KB limit",
            "request_id": getattr(g, "request_id", "unknown"),
        }), 413

    @app.errorhandler(500)
    def internal_error(_error):
        logger.exception("Unhandled application error")
        return jsonify({
            "error": "Internal server error",
            "request_id": getattr(g, "request_id", "unknown"),
        }), 500

    from app.models.database import init_db
    init_db()

    socketio.init_app(app)

    from app.controllers.realtime_controller import realtime_bp
    from app.controllers.ml_controller import ml_bp

    app.register_blueprint(realtime_bp)
    app.register_blueprint(ml_bp)

    @app.route("/health", methods=["GET"])
    def liveness():
        return jsonify({"status": "ok", "service": "soc-platform"})

    @app.route("/ready", methods=["GET"])
    def readiness():
        try:
            from app.controllers.ml_controller import detector
            ready = detector.model.model is not None
            status = "ready" if ready else "not_ready"
            return jsonify({
                "status": status,
                "model_version": detector.model.VERSION,
            }), (200 if ready else 503)
        except Exception:
            logger.exception("Readiness check failed")
            return jsonify({
                "status": "not_ready",
            }), 503

    return app
