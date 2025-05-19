from sqlalchemy import Column, String, Integer, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, index=True)
    name = Column(String)
    md5 = Column(String)
    type = Column(String)
    filetype = Column(String)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    threat_level = Column(String)
    detected = Column(Integer)
    total = Column(Integer)
