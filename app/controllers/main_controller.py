from flask import Blueprint, render_template, request, redirect, session, jsonify, send_file, flash
from app.services.correlation_service import correlate_attack
from app.services.log_service import generate_log
from app.services.detection_service import analyze_log
from app.services.ml_service import train_model
from app.services.risk_service import calculate_risk
from app.services.threat_service import threat_score
from app.services.geoip_service import get_geoip
from app.services.report_service import generate_report
from app.models.database import insert_log, get_logs
from app.models.auth import register_user, verify_user
from app import socketio
import jwt
import datetime
import threading
import time

main_bp = Blueprint("main", __name__)

SECRET = "supersecretjwtkey"

# ------------------------
# Initialize ML model once
# ------------------------
model = train_model()


# ------------------------
# HOME DASHBOARD
# ------------------------
@main_bp.route("/")
def home():
    if "user" not in session:
        return redirect("/login")

    logs = get_logs()

    brute_force_count = sum(1 for log in logs if "Failed login" in log[1])
    ddos_count = sum(1 for log in logs if "High traffic" in log[1])
    normal_count = sum(1 for log in logs if "Successful login" in log[1])
    risk_trend = [log[2] for log in logs[::-1]]

    risk = risk_trend[-1] if risk_trend else 0
    threat = logs[0][3] if logs else 0

    return render_template(
        "dashboard.html",
        logs=logs,
        risk=risk,
        threat=threat,
        brute_force_count=brute_force_count,
        ddos_count=ddos_count,
        normal_count=normal_count,
        risk_trend=risk_trend
    )


# ------------------------
# LOGIN
# ------------------------
from flask import flash

@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = verify_user(request.form["username"], request.form["password"])
        if role:
            session["user"] = request.form["username"]
            session["role"] = role
            flash("Login successful", "success")
            return redirect("/")
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")


# ------------------------
# REGISTER (Admin only)
# ------------------------
@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if "role" not in session or session["role"] != "Admin":
        return "Access Denied"

    if request.method == "POST":
        register_user(
            request.form["username"],
            request.form["password"],
            request.form["role"]
        )
        return redirect("/")

    return render_template("register.html")


# ------------------------
# LOGOUT
# ------------------------
@main_bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ------------------------
# ADMIN PANEL
# ------------------------
@main_bp.route("/admin")
def admin_panel():
    if "role" not in session or session["role"] != "Admin":
        return "Access Denied"
    return render_template("admin.html")


# ------------------------
# JWT API LOGIN
# ------------------------
@main_bp.route("/api/login", methods=["POST"])
def api_login():
    role = verify_user(request.json["username"], request.json["password"])

    if role:
        token = jwt.encode({
            "user": request.json["username"],
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET, algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"}), 401


# ------------------------
# PROTECTED API ENDPOINT
# ------------------------
@main_bp.route("/api/logs")
def api_logs():
    token = request.headers.get("Authorization")

    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
        logs = get_logs()
        return jsonify({"logs": logs})
    except:
        return jsonify({"error": "Invalid or expired token"}), 403


# ------------------------
# EXPORT REPORT
# ------------------------
@main_bp.route("/report")
def report():
    generate_report()
    return send_file("soc_report.pdf", as_attachment=True)

def background_soc_engine():
    while True:
        log = generate_log()
        alert = analyze_log(log)

        activity_score = 5
        prediction = model.predict([[activity_score]])[0]

        risk = calculate_risk(log, prediction)

        ip = log.split()[-1]
        threat = threat_score(ip)

        insert_log(log, risk, threat)

        lat, lon = get_geoip(ip)

        logs = get_logs()

        brute_force = sum(1 for l in logs if "Failed login" in l[1])
        ddos = sum(1 for l in logs if "High traffic" in l[1])
        normal = sum(1 for l in logs if "Successful login" in l[1])

        risk_trend = [l[2] for l in logs[::-1]]

        socketio.emit("dashboard_update", {
            "log": log,
            "alert": alert,
            "risk": risk,
            "threat": threat,
            "brute_force": brute_force,
            "ddos": ddos,
            "normal": normal,
            "risk_trend": risk_trend,
            "lat": lat,
            "lon": lon
        })

        time.sleep(3)

# ------------------------
# DOWNLOAD CSV
# ------------------------


@main_bp.route("/export_csv")
def export_csv():
    import csv
    import io
    from flask import Response
    from app.models.database import get_logs

    logs = get_logs(limit=None)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["Log", "Risk Score", "Threat Score"])

    for log in logs:
        writer.writerow([log[1], log[2], log[3]])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=analytics.csv"}
    )

# ------------------------
# FAVICON ICO
# ------------------------

@main_bp.route('/favicon.ico')
def favicon():
    from flask import send_from_directory
    return send_from_directory('static', 'favicon.ico')
