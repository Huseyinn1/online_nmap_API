from pydantic import BaseModel, IPvAnyAddress
import uuid
from typing import List, Optional
from datetime import datetime

class TargetRequest(BaseModel):
    ip: str

class ScanScriptRequest(BaseModel):
    ip: str
    script_name: str

class ScanTypeRequest(BaseModel):
    ip: str
    scan_types: List[str]
    port_range: Optional[str] = None  # Örnek: "1-1000" veya "80,443,8080"
    timing: Optional[str] = "T3"  # T0-T5 arası, varsayılan T3

class PortRangeRequest(BaseModel):
    ip: str
    start_port: int
    end_port: int

class ScanTemplateRequest(BaseModel):
    ip: str
    template_name: str
    options: str

class ScanScheduleRequest(BaseModel):
    ip: str
    scan_types: List[str]
    interval_minutes: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class ExportRequest(BaseModel):
    ip: str
    scan_types: List[str]
    format: str  # pdf, xml, html, csv

class ScanResult(BaseModel):
    scan_id: uuid.UUID
    status: str
    result: dict | None
