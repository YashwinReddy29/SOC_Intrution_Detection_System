
🛡 AI-Powered Cyber SOC Platform

A full-stack Security Operations Center (SOC) simulation platform featuring real-time threat detection, ML-based anomaly detection, JWT authentication, RBAC, WebSocket alerts, GeoIP visualization, and DevSecOps CI/CD integration.

🚀 Features

🔐 Secure Authentication (bcrypt hashed passwords)

🧑‍💼 Role-Based Access Control (Admin / Analyst)

🔑 JWT-secured REST API

⚡ Real-time WebSocket Alerts

🌍 GeoIP-based Live Attack Map

🤖 Machine Learning Anomaly Detection (Random Forest)

📊 Risk Scoring Engine

🧠 Threat Intelligence Scoring

🗄 SQLite Database Layer

🐳 Dockerized Deployment

🔁 GitHub Actions CI/CD

🔍 Static Security Scanning (Bandit)

📦 Dependency Vulnerability Scanning (Safety)

🏗 Architecture
Browser (HTTPS)
   ↓
Nginx Reverse Proxy
   ↓
Flask Application
   ↓
Redis (WebSocket Scaling)
   ↓
SQLite Database
   ↓
GeoIP External API

🧠 Technology Stack
Layer	Technology
Backend	Flask
Realtime	Flask-SocketIO
ML	Scikit-learn
Database	SQLite
Auth	JWT + bcrypt
DevOps	Docker
CI/CD	GitHub Actions
Security Scanning	Bandit + Safety
Reverse Proxy	Nginx
Cache	Redis
📦 Installation
1️⃣ Clone Repository
git clone https://github.com/yourusername/cyber-soc-platform.git
cd cyber-soc-platform

2️⃣ Create Virtual Environment
python -m venv venv
source venv/bin/activate

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Run Application
python run.py

🐳 Docker Deployment
docker build -t cyber-soc .
docker run -p 5000:5000 cyber-soc

🔐 Security Features

Passwords hashed using bcrypt

JWT-based API authentication

Role-based access control

CI security scanning

TLS termination via Nginx

Input validation checks

📊 Real-Time Features

Live attack detection

GeoIP attack mapping

Instant WebSocket alerts

Risk score visualization

🧪 CI/CD

On every push:

Syntax validation

Security scanning

Dependency audit

Docker build validation    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    socketio.init_app(app)
    return app
