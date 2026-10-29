ORBITAL AI SOC Platform

A Python-based Security Operations Center (SOC) platform designed to collect security events, detect suspicious login activity, assess risk, and manage security alerts through a web dashboard.

Overview

ORBITAL AI SOC Platform is a cybersecurity project that demonstrates core Security Operations Center workflows, including security event monitoring, brute-force detection, risk scoring, alert management, and automated testing.

The project aims to make security events easier to monitor and investigate through a centralized dashboard.

Features

- Security Event Collection: Receive and retrieve security events through API endpoints.
- Brute-Force Detection: Identify suspicious patterns involving repeated failed login attempts.
- Risk Scoring: Assign risk scores to security activity and classify its severity.
- Alert Management: Generate security alerts and track their status.
- Interactive Dashboard: View security events, alerts, and risk information in one interface.
- Alert Resolution: Mark alerts as resolved through the dashboard.
- Automated Scanning: Periodically scan recent security events for suspicious login activity.
- Automated Testing: Use pytest to test application functionality.

Technology Stack

- Python 3.12
- FastAPI
- SQLAlchemy
- SQLite
- Uvicorn
- Pytest
- HTML, CSS, and JavaScript

Project Structure

ai_soc_platform/
├── app/
│   ├── main.py
│   ├── detection.py
│   ├── risk_engine.py
│   ├── models.py
│   ├── database.py
│   ├── events.py
│   ├── alerts.py
│   ├── dashboard.py
│   └── static/
│       └── dashboard.html
├── tests/
│   ├── test_api.py
│   ├── test_detection.py
│   └── test_risk_engine.py
├── requirements.txt
├── .gitignore
└── README.md

Getting Started

1. Clone the Repository

git clone https://github.com/zeina-2006/AI-SOC-Platform-.git
cd AI-SOC-Platform-

2. Create a Virtual Environment

python -m venv venv

Activate it on Windows PowerShell:

.\venv\Scripts\Activate.ps1

3. Install Dependencies

python -m pip install -r requirements.txt

4. Run the Application

uvicorn app.main:app --reload

Open the following URLs in your browser:

- Dashboard: http://127.0.0.1:8000/
- API Documentation: http://127.0.0.1:8000/docs
- Health Check: http://127.0.0.1:8000/health

Run Tests

python -m pytest tests/ -v

Security Notice

This project is intended for educational and defensive cybersecurity purposes. Its detection capabilities are designed to demonstrate SOC concepts and should not be considered a replacement for a production-grade security monitoring system.

Author

Zeinab Mohamed

Cybersecurity Project | Python | Security Monitoring | FastAPI

GitHub: https://github.com/zeina-2006/AI-SOC-Platform-