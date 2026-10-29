import asyncio
import re
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.events import SecurityEvent
from app.database import Base, engine, SessionLocal
from app.models import SecurityEventDB, SecurityAlertDB
from app.detection import detect_brute_force, parse_timestamp
from app.risk_engine import calculate_risk_score
from app.dashboard import router as dashboard_router


BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_FILE = BASE_DIR / "static" / "dashboard.html"

Base.metadata.create_all(bind=engine)

WINDOW_MINUTES = 5
FAILED_LOGIN_THRESHOLD = 5


def get_failed_attempts(message):
    match = re.search(r"Failed attempts:\s*(\d+)", message or "")
    return int(match.group(1)) if match else 0


def scan_security_events():
    db = SessionLocal()

    try:
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(minutes=WINDOW_MINUTES)

        events = db.query(SecurityEventDB).all()
        recent_events = []

        for event in events:
            if event.event_type != "failed_login":
                continue

            event_time = parse_timestamp(event.timestamp)

            if event_time is None:
                continue

            if window_start <= event_time <= now:
                recent_events.append(event)

        suspicious_ips = detect_brute_force(recent_events)
        results = []

        for ip in suspicious_ips:
            attempts = sum(
                1 for event in recent_events
                if str(event.source_ip) == ip
            )

            if attempts < FAILED_LOGIN_THRESHOLD:
                continue

            risk = calculate_risk_score(attempts)

            alert = (
                db.query(SecurityAlertDB)
                .filter(
                    SecurityAlertDB.source_ip == ip,
                    SecurityAlertDB.alert_type == "Brute Force"
                )
                .order_by(SecurityAlertDB.id.desc())
                .first()
            )

            message = (
                f"{risk['reason']} "
                f"Source IP: {ip}. "
                f"Failed attempts: {attempts}. "
                f"Risk Score: {risk['risk_score']}/100. "
                f"Detection window: {WINDOW_MINUTES} minutes. "
                f"Recommended action: {risk['recommendation']}"
            )

            if alert and alert.status == "Active":
                alert.severity = risk["severity"]
                alert.risk_score = risk["risk_score"]
                alert.message = message
                action = "updated"

            elif alert and alert.status == "Resolved":
                previous_attempts = get_failed_attempts(alert.message)

                if attempts <= previous_attempts:
                    continue

                alert = SecurityAlertDB(
                    alert_type="Brute Force",
                    severity=risk["severity"],
                    risk_score=risk["risk_score"],
                    source_ip=ip,
                    message=message,
                    status="Active"
                )
                db.add(alert)
                action = "created"

            else:
                alert = SecurityAlertDB(
                    alert_type="Brute Force",
                    severity=risk["severity"],
                    risk_score=risk["risk_score"],
                    source_ip=ip,
                    message=message,
                    status="Active"
                )
                db.add(alert)
                action = "created"

            db.flush()

            results.append({
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "source_ip": ip,
                "severity": risk["severity"],
                "risk_score": risk["risk_score"],
                "failed_attempts": attempts,
                "status": alert.status,
                "action": action
            })

        db.commit()

        return {
            "suspicious_ips": suspicious_ips,
            "window_minutes": WINDOW_MINUTES,
            "threshold": FAILED_LOGIN_THRESHOLD,
            "recent_failed_events": len(recent_events),
            "alerts": results,
            "message": "Security scan completed"
        }

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


async def automatic_scan():
    while True:
        await asyncio.sleep(60)

        try:
            result = await asyncio.to_thread(scan_security_events)
            print(
                "[AUTO SCAN] Completed. Suspicious IPs:",
                result["suspicious_ips"]
            )
        except Exception as error:
            print(f"[AUTO SCAN ERROR] {error}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(automatic_scan())
    print("[AUTO SCAN] Enabled. First scan in 60 seconds.")

    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


app = FastAPI(
    title="AI SOC Platform",
    description="Security Operations Center API",
    version="1.0.0",
    lifespan=lifespan
)

# Serve the dashboard's static files.
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static"
)


@app.get("/", include_in_schema=False)
def root():
    if not DASHBOARD_FILE.is_file():
        raise HTTPException(
            status_code=500,
            detail=f"Dashboard file not found: {DASHBOARD_FILE}"
        )

    return FileResponse(DASHBOARD_FILE)


app.include_router(dashboard_router)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/events")
def receive_event(event: SecurityEvent):
    db = SessionLocal()

    try:
        db_event = SecurityEventDB(
            timestamp=event.timestamp,
            source=event.source,
            event_type=event.event_type,
            username=event.username,
            source_ip=str(event.source_ip)
        )

        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        return {
            "message": "Security event saved",
            "event": db_event.id
        }

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.get("/events")
def get_events():
    db = SessionLocal()

    try:
        events = (
            db.query(SecurityEventDB)
            .order_by(SecurityEventDB.id.desc())
            .all()
        )

        return [
            {
                "id": event.id,
                "timestamp": event.timestamp,
                "source": event.source,
                "event_type": event.event_type,
                "username": event.username,
                "source_ip": event.source_ip
            }
            for event in events
        ]

    finally:
        db.close()


@app.get("/detect")
def run_detection():
    return scan_security_events()


@app.get("/alerts")
def get_alerts():
    db = SessionLocal()

    try:
        alerts = (
            db.query(SecurityAlertDB)
            .order_by(SecurityAlertDB.id.desc())
            .all()
        )

        return [
            {
                "id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "source_ip": alert.source_ip,
                "message": alert.message,
                "status": alert.status or "Active"
            }
            for alert in alerts
        ]

    finally:
        db.close()


@app.post("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    db = SessionLocal()

    try:
        alert = (
            db.query(SecurityAlertDB)
            .filter(SecurityAlertDB.id == alert_id)
            .first()
        )

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        if alert.status == "Resolved":
            return {
                "message": "Alert is already resolved",
                "alert_id": alert.id,
                "status": alert.status
            }

        alert.status = "Resolved"
        db.commit()
        db.refresh(alert)

        return {
            "message": "Alert resolved successfully",
            "alert_id": alert.id,
            "status": alert.status
        }

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()