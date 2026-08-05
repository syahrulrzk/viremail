from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.session import get_db
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from datetime import datetime

router = APIRouter()


class WebhookCreate(BaseModel):
    url: HttpUrl
    events: List[str] = ["scan.completed"]
    secret: Optional[str] = None


class WebhookUpdate(BaseModel):
    url: Optional[HttpUrl] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None


class WebhookResponse(BaseModel):
    id: int
    url: str
    events: List[str]
    active: bool
    created_at: datetime


@router.post("", response_model=WebhookResponse)
async def create_webhook(request: WebhookCreate, db: Session = Depends(get_db)):
    # TODO: Implement webhook creation
    return {
        "id": 1,
        "url": str(request.url),
        "events": request.events,
        "active": True,
        "created_at": datetime.utcnow()
    }


@router.get("", response_model=List[WebhookResponse])
async def list_webhooks(db: Session = Depends(get_db)):
    # TODO: Implement list webhooks
    return []


@router.delete("/{webhook_id}")
async def remove_webhook(webhook_id: int, db: Session = Depends(get_db)):
    # TODO: Implement remove webhook
    return {"message": f"Webhook {webhook_id} removed"}


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(webhook_id: int, request: WebhookUpdate, db: Session = Depends(get_db)):
    # TODO: Implement update webhook
    return {
        "id": webhook_id,
        "url": str(request.url) if request.url else "https://example.com/webhook",
        "events": request.events or ["scan.completed"],
        "active": True,
        "created_at": datetime.utcnow()
    }
