from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.config import settings
from app.api.v1.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# CORS — origins come from settings (override via BACKEND_CORS_ORIGINS in .env)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.BACKEND_CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {"message": "VIRE API — Verified Intelligence & Recon Engine", "version": settings.VERSION}


@app.get("/health")
async def health():
    return {"status": "healthy"}
