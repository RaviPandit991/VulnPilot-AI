"""SQLAlchemy models for VulnPilot AI."""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    operator: Mapped[str] = mapped_column(String(128))
    mode: Mapped[str] = mapped_column(String(16), default="safe")
    status: Mapped[str] = mapped_column(String(32), default="pending")
    authorization_ref: Mapped[Optional[str]] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    notes: Mapped[Optional[str]] = mapped_column(Text)

    services: Mapped[List["Service"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    exploit_runs: Mapped[List["ExploitRun"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    name: Mapped[Optional[str]] = mapped_column(String(64))
    product: Mapped[Optional[str]] = mapped_column(String(128))
    version: Mapped[Optional[str]] = mapped_column(String(64))
    banner: Mapped[Optional[str]] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(16), default="open")
    # Operator-driven flags
    in_scope: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="services")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    service_id: Mapped[Optional[int]] = mapped_column(ForeignKey("services.id"))
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    cvss: Mapped[Optional[float]] = mapped_column(Float)
    severity: Mapped[Optional[str]] = mapped_column(String(16))
    remediation: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")


class ExploitRun(Base):
    __tablename__ = "exploit_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    module: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(32), default="check")
    options: Mapped[Optional[str]] = mapped_column(Text)
    result: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    safe_mode: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped[Scan] = relationship(back_populates="exploit_runs")


class ApplicableModule(Base):
    """Auto-discovered Metasploit `exploit/*` modules whose CVE matches a
    finding in `scan_id`.

    Populated by `exploit_engine.auto_discovery.discover_for_scan` when
    the operator clicks the Analyze button on the Exploit tab. Each row
    represents 'Metasploit thinks this module targets a CVE that recon
    found in this scan' - the module is therefore added to the runtime
    allowlist for that scan, so the operator can launch it from the UI
    without us having to ship every possible module in the curated
    catalog.
    """
    __tablename__ = "applicable_modules"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    service_id: Mapped[Optional[int]] = mapped_column(ForeignKey("services.id"))
    module: Mapped[str] = mapped_column(String(255))
    cve_id: Mapped[Optional[str]] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(16), default="auto")  # auto | manual
    name: Mapped[Optional[str]] = mapped_column(String(255))
    description: Mapped[Optional[str]] = mapped_column(Text)
    rank: Mapped[Optional[str]] = mapped_column(String(32))
    disclosure_date: Mapped[Optional[str]] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("scan_id", "module",
                         name="uq_applicable_scan_module"),
    )
