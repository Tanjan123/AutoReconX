from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from autoreconx.storage.database import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class ScanRecord(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(
        String,
        primary_key=True,
    )

    target: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )


class AssetRecord(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.scan_id"),
        nullable=False,
        index=True,
    )

    asset_type: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    asset_key: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    data_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    sources_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "asset_type",
            "asset_key",
            name="uq_scan_asset",
        ),
    )


class RelationshipRecord(Base):
    __tablename__ = "relationships"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.scan_id"),
        nullable=False,
        index=True,
    )

    source_type: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    source_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    relationship: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    target_type: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    target_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    evidence_source: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )
