from sqlalchemy import create_all, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime

Base = declarative_base()

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationship: One Case has Many Evidence items
    evidence = relationship("Evidence", back_populates="owner_case")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, index=True)
    type = Column(String) # URL, File, etc.
    value = Column(String)
    verdict = Column(String)
    risk_score = Column(Integer)
    case_id = Column(Integer, ForeignKey("cases.id"))
    
    owner_case = relationship("Case", back_populates="evidence")