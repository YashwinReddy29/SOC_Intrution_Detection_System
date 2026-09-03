import json
import logging
import time
import uuid

from flask import Flask, g, jsonify, request
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="gevent")
logger = logging.getLogger("soc")


def create_app():
    """Create the Flask application with event-driven ML detection."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "supersecretkey"
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    @app.before_request
    def attach_request_context():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.request_started = time.perf_counter()

    @app.after_request
    def add_request_headers(response):
        request_id = getattr(g, "request_id", "unknown")
        response.headers["X-Request-ID"] = request_id
        duration_ms = (time.perf_counter() - getattr(g, "request_started", time.perf_counter())) * 1000.0
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
        except Exception as exc:
            logger.exception("Readiness check failed")
            return jsonify({
                "status": "not_ready",
                "error": str(exc),
            }), 503

    return app
