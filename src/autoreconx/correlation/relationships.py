from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RelationshipType(str, Enum):
    RESOLVES_TO = "resolves_to"
    EXPOSES = "exposes"
    RUNS = "runs"
    SERVES = "serves"
    CONTAINS = "contains"


@dataclass(frozen=True)
class AssetRelationship:
    source_type: str
    source_id: str

    relationship: RelationshipType

    target_type: str
    target_id: str

    evidence_source: str
