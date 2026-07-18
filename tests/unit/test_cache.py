"""Unit tests for the audit cache system."""

from __future__ import annotations

from pathlib import Path

from contract_audit.core.cache import AuditCache, calculate_hash
from contract_audit.core.models import (
    Confidence,
    Finding,
    FindingCategory,
    Severity,
    SourceLocation,
)


def test_hash_calculation():
    content = "pragma solidity ^0.8.20;\ncontract Test {}"
    h1 = calculate_hash(content)
    h2 = calculate_hash(content)
    assert h1 == h2
    assert len(h1) == 64


def test_cache_save_and_load(tmp_path: Path):
    cache = AuditCache(tmp_path)
    cache.load()
    assert cache.data == {}

    file_path = "src/Test.sol"
    file_hash = calculate_hash("content")

    finding = Finding(
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=FindingCategory.REENTRANCY,
        source="test",
        detector_name="test-detector",
        locations=[
            SourceLocation(
                file=file_path,
                start_line=10,
                end_line=10,
                contract="Test"
            )
        ]
    )

    cache.update_file_cache(file_path, file_hash, [finding])
    cache.save()

    # Load in new cache instance
    new_cache = AuditCache(tmp_path)
    new_cache.load()

    assert file_path in new_cache.data
    assert new_cache.data[file_path]["hash"] == file_hash

    cached_findings = new_cache.get_cached_findings(file_path, file_hash)
    assert cached_findings is not None
    assert len(cached_findings) == 1
    assert cached_findings[0].title == "Test Finding"
    assert cached_findings[0].category == FindingCategory.REENTRANCY


def test_cache_miss_on_hash_mismatch(tmp_path: Path):
    cache = AuditCache(tmp_path)
    file_path = "src/Test.sol"

    cache.update_file_cache(file_path, "old_hash", [])
    cache.save()

    # Different hash should trigger miss (None)
    assert cache.get_cached_findings(file_path, "new_hash") is None
