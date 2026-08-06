"""Atlas service — the knowledge-base write/read layer.

Replaces the old single-blob `vire_atlas` cache with the normalized atlas
knowledge model:
  - AtlasDomain  : current state of a scanned domain (confidence, counts)
  - AtlasHistory : append-only snapshot of every scan (cache source)
  - AtlasEmail   : normalized email node, deduped per (domain, email)
  - AtlasSource  : source catalog (website, mailto, jobportal, github…)
  - AtlasRelationship : graph edge email --found_in--> source (confidence)
  - AtlasSubdomain / AtlasDnsRecord : supporting intel

Every write is best-effort (never raises) so a cache write failure can never
fail a scan. A completed scan result stays queryable per entity AND the
latest history row still serves fast repeat lookups.
"""

import logging
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.atlas import (
    AtlasDomain,
    AtlasHistory,
    AtlasEmail,
    AtlasSource,
    AtlasRelationship,
    AtlasSubdomain,
    AtlasDnsRecord,
    AtlasPerson,
)
# Shared HRD classification — single source of truth (also used by portals).
from app.tasks.portals import HRD_LOCAL_RE

logger = logging.getLogger(__name__)


def _get_or_create_source(db: Session, name: str) -> AtlasSource | None:
    """Get-or-create an atlas source node by name."""
    if not name:
        return None
    row = db.query(AtlasSource).filter(AtlasSource.name == name).first()
    if row:
        return row
    row = AtlasSource(name=name)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        row = db.query(AtlasSource).filter(AtlasSource.name == name).first()
    return row


# ---------------------------------------------------------------------------
# Read: cache lookup
# ---------------------------------------------------------------------------

def lookup_cached(domain: str, mode: str) -> tuple | None:
    """Serve the cached result for (domain, mode) if it exists.

    Returns (result_payload, scanned_at, hits_after) or None. Uses the most
    recent AtlasHistory snapshot for that domain+mode. Opens + closes its own
    short-lived session so no DB connection is held during a long scan.
    """
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        node = (
            db.query(AtlasDomain)
            .filter(AtlasDomain.domain == domain, AtlasDomain.scan_mode == mode)
            .first()
        )
        if node is None or node.status != "completed":
            return None
        hist = (
            db.query(AtlasHistory)
            .filter(AtlasHistory.domain_id == node.id, AtlasHistory.scan_mode == mode)
            .order_by(AtlasHistory.id.desc())
            .first()
        )
        if hist is None or hist.result is None:
            return None
        node.hits = (node.hits or 0) + 1
        try:
            db.commit()
        except Exception:
            db.rollback()
        return hist.result, node.last_scanned_at, (node.hits or 1)
    except Exception:
        return None
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Write: persist a completed scan into the atlas
# ---------------------------------------------------------------------------

def save_scan_result(domain: str, mode: str, result: dict) -> None:
    """Upsert the knowledge base from a completed scan result. Best-effort."""
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        _persist(db, domain, mode, result)
    except Exception as e:
        db.rollback()
        logger.exception("Atlas save failed for %s (%s): %s", domain, mode, e)
    finally:
        db.close()


def _persist(db: Session, domain: str, mode: str, result: dict) -> None:
    results = result.get("results") or {}
    emails = results.get("emails") or []
    subdomains = results.get("subdomains") or []
    dns_records = results.get("dns_records") or {}
    posture = results.get("security_posture") or {}
    score = results.get("confidence_score") or 0

    # ---- 1) AtlasDomain node (current state) ----
    node = (
        db.query(AtlasDomain)
        .filter(AtlasDomain.domain == domain, AtlasDomain.scan_mode == mode)
        .first()
    )
    if node is None:
        node = AtlasDomain(domain=domain, scan_mode=mode)
        db.add(node)
    node.status = "completed"
    node.confidence_score = score
    node.emails_found = len(emails)
    node.subdomains_found = len(subdomains)
    node.security_posture = posture
    node.dns_summary = {k: len(v) for k, v in dns_records.items() if isinstance(v, list)}
    node.last_seen = _now()
    node.last_scanned_at = _now()
    db.flush()  # assign node.id

    # ---- 2) AtlasHistory — append-only snapshot (the cache row) ----
    db.add(AtlasHistory(
        domain_id=node.id,
        scan_mode=mode,
        status="completed",
        result=result,
        emails_found=len(emails),
        duration_ms=result.get("duration_ms"),
    ))

    # ---- 3) DNS records ----
    for rtype, values in dns_records.items():
        if not isinstance(values, list):
            continue
        for value in values:
            exists = (
                db.query(AtlasDnsRecord.id)
                .filter(
                    AtlasDnsRecord.domain_id == node.id,
                    AtlasDnsRecord.record_type == rtype,
                    AtlasDnsRecord.value == str(value),
                ).first()
            )
            if not exists:
                db.add(AtlasDnsRecord(
                    domain_id=node.id, record_type=rtype, value=str(value)))

    # ---- 4) Emails + source edges ----
    for item in emails:
        email_addr = item.get("email") or ""
        if not email_addr or "@" not in email_addr:
            continue
        source_name = item.get("source") or "website"
        local = email_addr.split("@")[0].lower()
        smtp = item.get("smtp") or "unchecked"
        url = item.get("url") or ""

        email_node = (
            db.query(AtlasEmail)
            .filter(AtlasEmail.domain_id == node.id, AtlasEmail.email == email_addr)
            .first()
        )
        if email_node is None:
            email_node = AtlasEmail(
                domain_id=node.id, email=email_addr, local_part=local)
            db.add(email_node)
        email_node.smtp_status = smtp
        email_node.is_hrd = bool(HRD_LOCAL_RE.match(local))
        if smtp in ("ok", "rejected", "unknown"):
            email_node.last_verified_at = _now()
        email_node.last_seen = _now()
        db.flush()

        src = _get_or_create_source(db, source_name)
        if src is None:
            continue
        edge_exists = (
            db.query(AtlasRelationship.id)
            .filter(
                AtlasRelationship.email_id == email_node.id,
                AtlasRelationship.source_id == src.id,
                AtlasRelationship.url == (url or None),
            ).first()
        )
        if not edge_exists:
            db.add(AtlasRelationship(
                email_id=email_node.id, source_id=src.id, url=url or None,
                confidence=_confidence_for(source_name, smtp)))

    # ---- 5) Persons (GitHub / mailing-list / team-page contacts) ----
    people = results.get("people") or []
    for person in people:
        name = (person.get("name") or "").strip()
        email_addr = person.get("email") or ""
        if not name and not email_addr:
            continue
        db.add(AtlasPerson(
            domain_id=node.id,
            name=name or email_addr,
            source_name=person.get("source") or "github",
            context=person.get("context") or "",
            url=person.get("url") or "",
            is_hrd=bool(HRD_LOCAL_RE.match((email_addr or "").split("@")[0].lower())),
        ))

    # ---- 6) Subdomains ----
    for sub in subdomains:
        exists = (
            db.query(AtlasSubdomain.id)
            .filter(AtlasSubdomain.domain_id == node.id,
                    AtlasSubdomain.subdomain == sub).first()
        )
        if not exists:
            db.add(AtlasSubdomain(domain_id=node.id, subdomain=sub))

    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # concurrent scan for same domain — best-effort


def _now():
    from sqlalchemy.sql import func
    return func.now()


def _confidence_for(source_name: str, smtp: str) -> int:
    base = 60
    if smtp == "ok":
        base += 30
    elif smtp == "rejected":
        base -= 30
    if source_name in ("mailto",):
        base += 10
    return max(5, min(base, 99))
