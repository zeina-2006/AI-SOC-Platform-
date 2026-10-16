from pydantic import BaseModel, Field, IPvAnyAddress


class SecurityEvent(BaseModel):
    timestamp: str = Field(min_length=1)
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    username: str = Field(min_length=1)
    source_ip: IPvAnyAddress