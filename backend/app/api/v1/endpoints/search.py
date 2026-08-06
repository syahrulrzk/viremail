from fastapi import APIRouter
from celery.exceptions import TimeoutError as CeleryTimeoutError
from app.tasks.domain_tasks import DEFAULT_SOURCES, MODE_SOURCES, SOURCE_KEYS, process_domain_search
from app.tasks.portals import search_job_portals
from app.services import atlas_service
from pydantic import BaseModel, Field, field_validator

router = APIRouter()


class DomainSearchRequest(BaseModel):
    domain: str
    mode: str = "smart"  # quick | smart | deep — validated below against MODE_SOURCES
    deep: bool = False  # legacy alias: deep=True forces mode="deep" (BBOT + Holehe)
    force: bool = False  # Skip the Atlas cache and re-scan from scratch
    sources: list[str] = Field(default_factory=lambda: list(DEFAULT_SOURCES))

    @field_validator("mode")
    @classmethod
    def clean_mode(cls, v: str) -> str:
        v = (v or "smart").strip().lower()
        return v if v in MODE_SOURCES else "smart"

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


class JobPortalSearchRequest(BaseModel):
    keyword: str = Field(..., min_length=2, max_length=80)
    location: str = Field(default="", max_length=80)
    max_pages: int = Field(default=20, ge=5, le=60)

    @field_validator("keyword")
    @classmethod
    def clean_keyword(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("location")
    @classmethod
    def clean_location(cls, v: str) -> str:
        return (v or "").strip()


@router.post("/domain")
def search_domain(request: DomainSearchRequest):
    mode = "deep" if request.deep else request.mode

    # ---- Atlas knowledge base: serve the latest cached scan instead of a
    #      full re-scan (reads the most recent AtlasHistory snapshot) ----
    cached = None
    if not request.force:
        cached = atlas_service.lookup_cached(request.domain, mode)
    if cached is not None:
        payload, scanned_at, hits = cached
        payload = dict(payload)
        payload["from_cache"] = True
        payload["cached_at"] = (
            scanned_at.isoformat() if scanned_at is not None else None
        )
        payload["cached_hits"] = hits
        return payload

    try:
        task = process_domain_search.delay(
            request.domain, scan_id=1, mode=mode,
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

    # ---- Atlas knowledge base: persist the fresh result (best-effort) ----
    if result.get("status") == "completed":
        atlas_service.save_scan_result(request.domain, mode, result)

    result["from_cache"] = False
    return result


@router.post("/jobportal")
def search_job_portal(request: JobPortalSearchRequest):
    """HRD Hunter — bulk HRD/recruitment email discovery from job portals.

    Polite, rate-limited scraping: discovery via public search engines
    (site: dorks), a bounded set of listing pages fetched with per-host
    delays, robots.txt honored, LinkedIn skipped. No portal is hammered.
    """
    try:
        task = search_job_portals.delay(
            keyword=request.keyword,
            location=request.location,
            max_pages=request.max_pages,
        )
    except Exception as e:
        return {
            "status": "error",
            "message": "Worker queue tidak tersedia. Pastikan Redis & Celery berjalan.",
            "error": str(e),
        }

    try:
        result = task.get(timeout=300)
    except CeleryTimeoutError:
        return {
            "status": "processing",
            "task_id": task.id,
            "message": "Pencarian masih berjalan di background. Coba lagi dalam beberapa detik.",
        }
    except Exception as e:
        return {
            "status": "error",
            "task_id": task.id,
            "message": "Pencarian gagal diproses oleh worker.",
            "error": str(e),
        }
    if result is None:
        return {
            "status": "processing",
            "task_id": task.id,
            "message": "Pencarian masih berjalan di background. Coba lagi dalam beberapa detik.",
        }
    return result
