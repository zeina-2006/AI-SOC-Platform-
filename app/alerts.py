from pydantic import BaseModel


class SecurityAlert(BaseModel):
    alert_type: str
    severity: str
    source_ip: str
    message: str