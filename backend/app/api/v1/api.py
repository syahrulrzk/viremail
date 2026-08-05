from fastapi import APIRouter
from app.api.v1.endpoints import search, auth, apikeys, webhooks

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(search.router, prefix="/search", tags=["search"])
api_router.include_router(apikeys.router, prefix="/apikeys", tags=["api-keys"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])


