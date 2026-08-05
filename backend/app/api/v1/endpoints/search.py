from fastapi import APIRouter
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func
from celery.exceptions import TimeoutError as CeleryTimeoutError
from app.tasks.domain_tasks import DEFAULT_SOURCES, SOURCE_KEYS, process_domain_search
from app.db.session import SessionLocal
from app.models.vire_atlas import VireAtlas
from pydantic import BaseModel, Field, field_validator

router = APIRouter()


class DomainSearchRequest(BaseModel):
    domain: str
    deep: bool = False  # Deep OSINT mode: also runs BBOT + Holehe (slower)
    force: bool = False  # Skip the VIRE Atlas cache and re-scan from scratch
    sources: list[str] = Field(default_factory=lambda: list(DEFAULT_SOURCES))

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        v = (v or "").strip().lower()
        # removeprefix, NOT lstrip/replace (lstrip would strip leading "w" chars)
        for prefix in ("https://", "http://", "www."):
            v = v.removeprefix(prefix)
        v = v.split("/")[0].split("@")[-1]
        if not v or "." not in v:
            raise ValueError("Masukkan domain yang valid, contoh: example.com")
        return v

    @field_validator("sources")
    @classmethod
    def clean_sources(cls, v: list[str]) -> list[str]:
        allowed = set(SOURCE_KEYS)
        cleaned = [s for s in v if s in allowed]
        return cleaned or list(DEFAULT_SOURCES)


def _lookup_atlas(domain: str, mode: str):
    """Return the cached row for (domain, mode) or None. Opens + closes its own
    short-lived session so no DB connection is held during a long scan."""
    db = SessionLocal()
    try:
        return (
            db.query(VireAtlas)
            .filter(VireAtlas.domain == domain, VireAtlas.scan_mode == mode)
            .first()
        )
    finally:
        db.close()


def _save_atlas(domain: str, mode: str, result: dict) -> None:
    """Upsert a completed scan result into the atlas. Best-effort — never raise."""
    db = SessionLocal()
    try:
        row = (
            db.query(VireAtlas)
            .filter(VireAtlas.domain == domain, VireAtlas.scan_mode == mode)
            .first()
        )
        emails_found = 0
        try:
            emails_found = len(result["results"].get("emails") or [])
        except Exception:
            pass
        now = func.now()
        if row:
            row.result = result
            row.emails_found = emails_found
            row.status = "completed"
            row.scanned_at = now
        else:
            db.add(VireAtlas(
                domain=domain,
                scan_mode=mode,
                result=result,
                emails_found=emails_found,
                status="completed",
                hits=0,
                scanned_at=now,
            ))
        try:
            db.commit()
        except IntegrityError:
            # Concurrent scan for the same domain won the race — update instead.
            db.rollback()
            row = (
                db.query(VireAtlas)
                .filter(VireAtlas.domain == domain, VireAtlas.scan_mode == mode)
                .first()
            )
            if row:
                row.result = result
                row.emails_found = emails_found
                row.status = "completed"
                row.scanned_at = func.now()
                db.commit()
    except Exception:
        db.rollback()  # cache write is best-effort — never fail the scan
    finally:
        db.close()


@router.post("/domain")
def search_domain(request: DomainSearchRequest):
    mode = "deep" if request.deep else "standard"

    # ---- VIRE Atlas: serve a cached result instead of a full re-scan ----
    cached = _lookup_atlas(request.domain, mode)
    if cached is not None and not request.force and cached.result is not None:
        db = SessionLocal()
        try:
            db.query(VireAtlas).filter(VireAtlas.id == cached.id).update(
                {VireAtlas.hits: (cached.hits or 0) + 1}
            )
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
        payload = dict(cached.result)
        payload["from_cache"] = True
        payload["cached_at"] = (
            cached.scanned_at or cached.created_at
        ).isoformat()
        payload["cached_hits"] = (cached.hits or 0) + 1
        return payload

    try:
        task = process_domain_search.delay(
            request.domain, scan_id=1, deep=request.deep,
            sources=request.sources)
    except Exception as e:
        return {
            "domain": request.domain,
            "status": "error",
            "message": "Worker queue tidak tersedia. Pastikan Redis & Celery berjalan.",
            "error": str(e),
        }

    # Wait for the worker synchronously (MVP). In production, poll a task endpoint.
    # Deep mode scans can take several minutes (BBOT + Holehe).
    try:
        result = task.get(timeout=600)
    # NOTE: celery.exceptions.TimeoutError is its OWN exception class (not a
    # subclass of builtins.TimeoutError) — catching builtins.TimeoutError here
    # would never fire and the timeout would fall through to the generic error
    # handler below (wrong "gagal" message while the task keeps running).
    except CeleryTimeoutError:
        return {
            "domain": request.domain,
            "status": "processing",
            "task_id": task.id,
            "message": "Pencarian masih berjalan di background. Coba lagi dalam beberapa detik.",
        }
    except Exception as e:
        return {
            "domain": request.domain,
            "status": "error",
            "task_id": task.id,
            "message": "Pencarian gagal diproses oleh worker.",
            "error": str(e),
        }
    if result is None:
        return {
            "domain": request.domain,
            "status": "processing",
            "task_id": task.id,
            "message": "Pencarian masih berjalan di background. Coba lagi dalam beberapa detik.",
        }

    # ---- VIRE Atlas: persist the fresh result for future fast lookups ----
    if result.get("status") == "completed":
        _save_atlas(request.domain, mode, result)

    result["from_cache"] = False
    return result
