from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="gevent")


def create_app():
    """Create the Flask application with event-driven ML detection."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "supersecretkey"

    from app.models.database import init_db
    init_db()

    socketio.init_app(app)

    # The clean dashboard controller replaces the legacy controller that
    # contained the 3-second polling loop and toy ML training.
    from app.controllers.realtime_controller import realtime_bp
    from app.controllers.ml_controller import ml_bp

    app.register_blueprint(realtime_bp)
    app.register_blueprint(ml_bp)

    return app
