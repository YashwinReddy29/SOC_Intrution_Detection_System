import threading
import time
from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*", async_mode="gevent")

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "supersecretkey"

    # Initialize DB FIRST
    from app.models.database import init_db
    init_db()

    socketio.init_app(app)

    from app.controllers.main_controller import main_bp
    app.register_blueprint(main_bp)

    # Import services AFTER DB initialized
    from app.services.log_service import generate_log
    from app.services.detection_service import analyze_log
    from app.services.ml_service import train_model
    from app.services.risk_service import calculate_risk
    from app.services.threat_service import threat_score
    from app.services.geoip_service import get_geoip
    from app.services.correlation_service import correlate_attack
    from app.models.database import insert_log, get_logs

    model = train_model()

    def background_task():
        while True:
            log = generate_log()
            alert = analyze_log(log)

            ip = log.split()[-1]

            prediction = model.predict([[5]])[0]
            risk = calculate_risk(log, prediction)
            threat = threat_score(ip)

            insert_log(log, risk, threat)

            lat, lon = get_geoip(ip)

            if not lat or not lon:
                import random
                lat = random.uniform(-60, 70)
                lon = random.uniform(-180, 180)

            correlation_alert = correlate_attack(
                ip,
                "Failed login" if "Failed login" in log else
                "High traffic" if "High traffic" in log else
                "Normal"
            )

            logs = get_logs()

            brute_force_count = sum(1 for l in logs if "Failed login" in l[1])
            ddos_count = sum(1 for l in logs if "High traffic" in l[1])
            normal_count = sum(1 for l in logs if "Successful login" in l[1])
            risk_trend = [l[2] for l in logs[::-1]]

            if alert:
                socketio.emit("new_alert", {"message": alert})

            if correlation_alert:
                socketio.emit("new_alert", {"message": correlation_alert})

            socketio.emit("new_attack", {"lat": lat, "lon": lon})

            socketio.emit("metrics_update", {
                "risk": risk,
                "threat": threat,
                "brute_force": brute_force_count,
                "ddos": ddos_count,
                "normal": normal_count,
                "risk_trend": risk_trend
            })

            time.sleep(3)

    # Start thread ONLY when app is created
    threading.Thread(target=background_task, daemon=True).start()

    return app
