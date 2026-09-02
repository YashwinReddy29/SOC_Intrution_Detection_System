from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="gevent")


def create_app():
    """Create the Flask application without a polling-based SOC loop."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "supersecretkey"

    from app.models.database import init_db
    init_db()

    socketio.init_app(app)

    from app.controllers.main_controller import main_bp
    from app.controllers.ml_controller import ml_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(ml_bp)

    return app
