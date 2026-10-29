from sqlalchemy import Column, Integer, String, text

from app.database import Base


class SecurityEventDB(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String, nullable=False)
    source = Column(String, nullable=False)
    event_type = Column(String, nullable=False)
    username = Column(String, nullable=False)
    source_ip = Column(String, nullable=False)


class SecurityAlertDB(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=True)
    source_ip = Column(String, nullable=False)
    message = Column(String, nullable=False)

    status = Column(
        String,
        nullable=False,
        default="Active",
        server_default=text("'Active'")
    )