from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from autoreconx.correlation import CorrelatedScanResult
from autoreconx.storage.database import (
    create_database_engine,
    create_session_factory,
    initialize_database,
)
from autoreconx.storage.tables import (
    AssetRecord,
    RelationshipRecord,
    ScanRecord,
)


def _json_default(value: Any) -> Any:
    """
    Convert values such as sets into JSON-safe structures.
    """

    if isinstance(value, set):
        return sorted(value)

    if hasattr(value, "isoformat"):
        return value.isoformat()

    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _serialize_asset(asset: object) -> str:
    """Serialize a correlated asset to JSON."""

    return json.dumps(
        asdict(asset),
        default=_json_default,
        sort_keys=True,
    )


def _serialize_sources(
    sources: set[str],
) -> str:
    """Serialize asset provenance deterministically."""

    return json.dumps(sorted(sources))


def _save_asset_group(
    session: Session,
    *,
    scan_id: str,
    asset_type: str,
    assets: dict[str, object],
) -> None:
    """Persist one group of correlated assets."""

    for asset_key, asset in assets.items():
        sources = getattr(
            asset,
            "sources",
            set(),
        )

        session.add(
            AssetRecord(
                scan_id=scan_id,
                asset_type=asset_type,
                asset_key=asset_key,
                data_json=_serialize_asset(asset),
                sources_json=_serialize_sources(sources),
            )
        )


def save_correlated_scan(
    result: CorrelatedScanResult,
    database_path: Path,
) -> Path:
    """
    Persist one correlated AutoReconX scan into SQLite.

    Returns the final database path.
    """

    engine = create_database_engine(database_path)

    initialize_database(engine)

    session_factory = create_session_factory(engine)

    with session_factory() as session:
        session.add(
            ScanRecord(
                scan_id=result.scan_id,
                target=result.target,
            )
        )

        _save_asset_group(
            session,
            scan_id=result.scan_id,
            asset_type="domain",
            assets=result.domains,
        )

        _save_asset_group(
            session,
            scan_id=result.scan_id,
            asset_type="ip",
            assets=result.ips,
        )

        _save_asset_group(
            session,
            scan_id=result.scan_id,
            asset_type="port",
            assets=result.ports,
        )

        _save_asset_group(
            session,
            scan_id=result.scan_id,
            asset_type="service",
            assets=result.services,
        )

        _save_asset_group(
            session,
            scan_id=result.scan_id,
            asset_type="web",
            assets=result.web_assets,
        )

        _save_asset_group(
            session,
            scan_id=result.scan_id,
            asset_type="endpoint",
            assets=result.endpoints,
        )

        for relationship in result.relationships:
            session.add(
                RelationshipRecord(
                    scan_id=result.scan_id,
                    source_type=relationship.source_type,
                    source_id=relationship.source_id,
                    relationship=relationship.relationship.value,
                    target_type=relationship.target_type,
                    target_id=relationship.target_id,
                    evidence_source=relationship.evidence_source,
                )
            )

        session.commit()

    return database_path
