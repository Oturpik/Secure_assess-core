"""
Database models for vulnerability and compliance data.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Framework(Base):
    """Security framework (NIST, CIS, OWASP) definition."""
    __tablename__ = 'frameworks'

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    version = Column(String(20), nullable=False)
    description = Column(Text)
    last_updated = Column(DateTime, default=datetime.utcnow)

    vulnerabilities = relationship('Vulnerability', back_populates='framework')
    controls = relationship('Control', back_populates='framework')


class Control(Base):
    """Security controls defined by frameworks."""
    __tablename__ = 'controls'

    id = Column(Integer, primary_key=True)
    framework_id = Column(Integer, ForeignKey('frameworks.id'), nullable=False)
    control_id = Column(String(50), nullable=False)  # e.g., 'CIS-1.1' or 'NIST-AC-1'
    title = Column(String(200), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    subcategory = Column(String(100))
    severity = Column(String(20))  # High, Medium, Low
    
    framework = relationship('Framework', back_populates='controls')
    vulnerability_mappings = relationship('VulnerabilityControlMapping', back_populates='control')


class Vulnerability(Base):
    """CVE and other vulnerability records."""
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    framework_id = Column(Integer, ForeignKey('frameworks.id'), nullable=False)
    cve_id = Column(String(20), unique=True)  # CVE-YYYY-NNNNN
    title = Column(Text)  # Changed from String(200) to Text for longer titles
    description = Column(Text)
    severity = Column(String(20))  # Critical, High, Medium, Low
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    affected_products = Column(JSON)  # List of affected products/versions
    references = Column(JSON)  # List of reference URLs
    mitigation = Column(Text)
    extra_data = Column(JSON)  # Additional framework-specific metadata
    
    framework = relationship('Framework', back_populates='vulnerabilities')
    control_mappings = relationship('VulnerabilityControlMapping', back_populates='vulnerability')


class VulnerabilityControlMapping(Base):
    """Maps vulnerabilities to framework controls."""
    __tablename__ = 'vulnerability_control_mappings'

    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=False)
    control_id = Column(Integer, ForeignKey('controls.id'), nullable=False)
    mapping_type = Column(String(50))  # direct, indirect, etc.
    confidence = Column(Float)  # confidence score of the mapping
    notes = Column(Text)
    
    vulnerability = relationship('Vulnerability', back_populates='control_mappings')
    control = relationship('Control', back_populates='vulnerability_mappings')


class ComplianceRequirement(Base):
    """Framework-specific compliance requirements."""
    __tablename__ = 'compliance_requirements'

    id = Column(Integer, primary_key=True)
    framework_id = Column(Integer, ForeignKey('frameworks.id'), nullable=False)
    requirement_id = Column(String(50), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    priority = Column(String(20))  # Must, Should, Optional
    validation_criteria = Column(JSON)
    implementation_guidance = Column(Text)
    
    framework = relationship('Framework')


class ScanResult(Base):
    """Results from vulnerability scans."""
    __tablename__ = 'scan_results'

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), unique=True, nullable=False)
    framework_id = Column(Integer, ForeignKey('frameworks.id'), nullable=False)
    repository_url = Column(String(200))
    branch = Column(String(100))
    commit_hash = Column(String(40))
    scan_date = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20))  # completed, failed, in-progress
    findings = Column(JSON)
    compliance_score = Column(Float)
    raw_output = Column(JSON)
    
    framework = relationship('Framework')
