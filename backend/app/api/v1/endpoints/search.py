from fastapi import APIRouter
from celery.exceptions import TimeoutError as CeleryTimeoutError
from app.tasks.domain_tasks import DEFAULT_SOURCES, SOURCE_KEYS, process_domain_search
from pydantic import BaseModel, Field, field_validator

router = APIRouter()


class DomainSearchRequest(BaseModel):
    domain: str
    deep: bool = False  # Deep OSINT mode: also runs BBOT + Holehe (slower)
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


# Sync handler: FastAPI runs it in a threadpool, so the blocking task.get()
# below never stalls the event loop (async handlers would freeze /health, etc.).
@router.post("/domain")
def search_domain(request: DomainSearchRequest):
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
    return result
