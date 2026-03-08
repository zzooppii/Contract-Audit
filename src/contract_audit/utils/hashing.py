"""Finding fingerprint and deduplication utilities."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from ..core.models import Finding, SourceLocation

# Severity ordering for keeping the most important finding
_SEVERITY_ORDER = {
    "Critical": 6, "High": 5, "Medium": 4,
    "Low": 3, "Informational": 2, "Gas": 1,
}
_CONFIDENCE_ORDER = {"High": 3, "Medium": 2, "Low": 1}


def fingerprint(category: str, title: str, locations: list[SourceLocation]) -> str:
    """Generate a stable fingerprint for deduplication."""
    loc_strs = sorted(str(loc) for loc in locations)
    content = f"{category}:{title}:{':'.join(loc_strs)}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _primary_file_line(finding: Finding) -> tuple[str, int] | None:
    """Get the primary (file, start_line) for a finding."""
    if finding.locations:
        loc = finding.locations[0]
        return (loc.file, loc.start_line)
    return None


def _locations_overlap(f1: Finding, f2: Finding) -> bool:
    """Check if two findings share any overlapping line ranges in the same file."""
    for loc1 in f1.locations:
        for loc2 in f2.locations:
            # Normalize file paths — strip leading path components for comparison
            f1_name = loc1.file.rsplit("/", 1)[-1]
            f2_name = loc2.file.rsplit("/", 1)[-1]
            if f1_name != f2_name:
                continue
            # Check overlap: lines within 3 of each other are "same location"
            if abs(loc1.start_line - loc2.start_line) <= 3:
                return True
    return False


def _sev_score(finding: Finding) -> int:
    return _SEVERITY_ORDER.get(finding.severity.value, 0)


def _conf_score(finding: Finding) -> int:
    return _CONFIDENCE_ORDER.get(finding.confidence.value, 0)


def _is_better(candidate: Finding, existing: Finding) -> bool:
    """Return True if candidate should replace existing."""
    if _sev_score(candidate) > _sev_score(existing):
        return True
    if _sev_score(candidate) == _sev_score(existing):
        return _conf_score(candidate) > _conf_score(existing)
    return False


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings using two-phase dedup.

    Phase 1: Exact fingerprint match (same category + title + location)
    Phase 2: Same category + overlapping location → keep highest severity
    """
    # Phase 1: Exact fingerprint dedup
    by_fp: dict[str, Finding] = {}
    for finding in findings:
        fp = finding.fingerprint
        if fp not in by_fp:
            by_fp[fp] = finding
        elif _is_better(finding, by_fp[fp]):
            # Merge source info before replacing
            existing = by_fp[fp]
            finding.metadata.setdefault("additional_sources", [])
            if existing.source != finding.source:
                finding.metadata["additional_sources"].append(existing.source)
            by_fp[fp] = finding
        else:
            existing = by_fp[fp]
            if finding.source != existing.source:
                existing.metadata.setdefault("additional_sources", []).append(finding.source)

    phase1 = list(by_fp.values())

    # Phase 2: Merge findings of the same category at overlapping locations.
    by_category: dict[str, list[Finding]] = defaultdict(list)
    for f in phase1:
        by_category[f.category.value].append(f)

    phase2: list[Finding] = []
    for category, group in by_category.items():
        merged = _merge_overlapping(group)
        phase2.extend(merged)

    # Phase 3: Consolidate same detector + same file into one finding.
    # e.g. 6x "Unchecked ERC20 Transfer" in the same file → 1 finding with all locations.
    phase3 = _consolidate_same_detector(phase2)

    return phase3


def _merge_overlapping(group: list[Finding]) -> list[Finding]:
    """Within a same-category group, merge findings at overlapping locations.

    Only merges findings from the SAME source/detector — different detectors
    flagging the same location are distinct findings that should both be kept.
    """
    if len(group) <= 1:
        return group

    # Sort by severity desc so we process the most important first
    group.sort(key=lambda f: (_sev_score(f), _conf_score(f)), reverse=True)

    kept: list[Finding] = []
    consumed: set[int] = set()

    for i, fi in enumerate(group):
        if i in consumed:
            continue
        merged_sources = set()
        merged_sources.add(fi.source)
        for extra in fi.metadata.get("additional_sources", []):
            merged_sources.add(extra)

        for j, fj in enumerate(group):
            if j <= i or j in consumed:
                continue
            # Only merge if same detector AND overlapping location
            if fi.detector_name == fj.detector_name and _locations_overlap(fi, fj):
                consumed.add(j)
                merged_sources.add(fj.source)
                for extra in fj.metadata.get("additional_sources", []):
                    merged_sources.add(extra)

        merged_sources.discard(fi.source)
        if merged_sources:
            fi.metadata["additional_sources"] = sorted(merged_sources)

        kept.append(fi)

    return kept


def _consolidate_same_detector(findings: list[Finding]) -> list[Finding]:
    """Merge findings from the same Slither detector in the same file into one entry.

    For example, 6 'unchecked-transfer' findings in LendingVault.sol become
    one finding with 6 locations, or 3 'reentrancy-benign' become one.
    Only consolidates when detector_name matches exactly and findings share a file.
    """
    # Group by (detector_name, primary_file)
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    ungrouped: list[Finding] = []

    for f in findings:
        det = f.detector_name
        if not det or det == "unknown":
            ungrouped.append(f)
            continue
        primary = f.locations[0].file.rsplit("/", 1)[-1] if f.locations else ""
        if not primary:
            ungrouped.append(f)
            continue
        groups[(det, primary)].append(f)

    result: list[Finding] = list(ungrouped)
    for (det, _file), group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Keep the highest severity/confidence, merge all locations
        group.sort(key=lambda f: (_sev_score(f), _conf_score(f)), reverse=True)
        best = group[0]

        # Collect all unique locations
        seen_locs: set[tuple[str, int]] = set()
        all_locations: list[SourceLocation] = []
        for f in group:
            for loc in f.locations:
                key = (loc.file, loc.start_line)
                if key not in seen_locs:
                    seen_locs.add(key)
                    all_locations.append(loc)

        # Update the best finding
        best.locations = all_locations
        # Update title to remove function-specific suffix
        func_names = []
        for f in group:
            # Extract function name from title like "Unchecked ERC20 Transfer: deposit"
            if ": " in f.title:
                func_names.append(f.title.split(": ", 1)[1])
        if func_names:
            base_title = best.title.split(": ", 1)[0]
            best.title = f"{base_title} ({len(group)} instances)"

        # Merge sources
        sources = set()
        sources.add(best.source)
        for f in group:
            sources.add(f.source)
            for s in f.metadata.get("additional_sources", []):
                sources.add(s)
        sources.discard(best.source)
        if sources:
            best.metadata["additional_sources"] = sorted(sources)

        best.metadata["consolidated_count"] = len(group)
        # Recompute fingerprint
        best.fingerprint = fingerprint(best.category.value, best.title, best.locations)
        result.append(best)

    return result


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    """Link related findings by location overlap."""
    for i, f1 in enumerate(findings):
        for j, f2 in enumerate(findings):
            if i >= j:
                continue
            # Check if findings share a file
            f1_files = {loc.file for loc in f1.locations}
            f2_files = {loc.file for loc in f2.locations}
            if f1_files & f2_files:
                if f2.fingerprint not in f1.related_findings:
                    f1.related_findings.append(f2.fingerprint)
                if f1.fingerprint not in f2.related_findings:
                    f2.related_findings.append(f1.fingerprint)
    return findings
