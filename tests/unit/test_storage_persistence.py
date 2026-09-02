from pathlib import Path

from sqlalchemy import func, select

from autoreconx.correlation import correlate_scan
from autoreconx.models import (
    DomainAsset,
    IPAsset,
    PortAsset,
    ScanResult,
)
from autoreconx.storage.database import (
    create_database_engine,
    create_session_factory,
)
from autoreconx.storage.persistence import (
    save_correlated_scan,
)
from autoreconx.storage.tables import (
    AssetRecord,
    RelationshipRecord,
    ScanRecord,
)


def test_save_correlated_scan(
    tmp_path: Path,
):
    scan = ScanResult(
        scan_id="test-scan",
        target="example.com",
    )

    scan.domains.append(
        DomainAsset(
            hostname="example.com",
            source="target",
        )
    )

    scan.ips.append(
        IPAsset(
            address="10.0.0.1",
            source="dnsx",
        )
    )

    scan.ports.append(
        PortAsset(
            ip="10.0.0.1",
            port=443,
            source="naabu",
        )
    )

    correlated = correlate_scan(scan)

    database_path = (
        tmp_path / "autoreconx.db"
    )

    save_correlated_scan(
        correlated,
        database_path,
    )

    assert database_path.exists()

    engine = create_database_engine(
        database_path
    )

    session_factory = create_session_factory(
        engine
    )

    with session_factory() as session:
        scan_count = session.scalar(
            select(func.count())
            .select_from(ScanRecord)
        )

        asset_count = session.scalar(
            select(func.count())
            .select_from(AssetRecord)
        )

        relationship_count = session.scalar(
            select(func.count())
            .select_from(RelationshipRecord)
        )

    assert scan_count == 1
    assert asset_count == 3
    assert relationship_count == 1
