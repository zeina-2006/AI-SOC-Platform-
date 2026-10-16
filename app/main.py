from contextlib import asynccontextmanager, suppress
import asyncio

from fastapi import FastAPI

from app.events import SecurityEvent
from app.database import Base, engine, SessionLocal
from app.models import SecurityEventDB, SecurityAlertDB
from app.detection import detect_brute_force
from app.risk_engine import calculate_risk_score
from app.dashboard import router as dashboard_router

Base.metadata.create_all(bind=engine)


def scan_security_events():
    db = SessionLocal()

    try:
        events = db.query(SecurityEventDB).all()
        suspicious_ips = detect_brute_force(events)
        results = []

        for ip in suspicious_ips:
            attempts = sum(
                1 for event in events
                if str(event.source_ip) == ip
                and event.event_type == "failed_login"
            )

            risk = calculate_risk_score(attempts)

            alert = (
                db.query(SecurityAlertDB)
                .filter(
                    SecurityAlertDB.source_ip == ip,
                    SecurityAlertDB.alert_type == "Brute Force"
                )
                .first()
            )

            message = (
                f"{risk['reason']} "
                f"Source IP: {ip}. "
                f"Risk Score: {risk['risk_score']}/100. "
                f"Recommended action: {risk['recommendation']}"
            )

            if alert:
                alert.severity = risk["severity"]
                alert.risk_score = risk["risk_score"]
                alert.message = message
                status = "updated"
            else:
                alert = SecurityAlertDB(
                    alert_type="Brute Force",
                    severity=risk["severity"],
                    risk_score=risk["risk_score"],
                    source_ip=ip,
                    message=message
                )
                db.add(alert)
                status = "created"

            db.flush()

            results.append({
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "source_ip": ip,
                "severity": risk["severity"],
                "risk_score": risk["risk_score"],
                "failed_attempts": attempts,
                "reason": risk["reason"],
                "recommendation": risk["recommendation"],
                "status": status
            })

        db.commit()

        return {
            "suspicious_ips": suspicious_ips,
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

app.include_router(dashboard_router)


@app.get("/")
def root():
    return {
        "message": "AI SOC Platform is running",
        "status": "online"
    }


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
                "message": alert.message
            }
            for alert in alerts
        ]
    finally:
        db.close()