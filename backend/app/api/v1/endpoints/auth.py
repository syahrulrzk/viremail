from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


@router.post("/login")
async def login(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    # TODO: Implement actual authentication
    return {"access_token": "dummy_token", "token_type": "bearer"}


@router.post("/register")
async def register(db: Session = Depends(get_db)):
    # TODO: Implement registration
    return {"message": "Registration endpoint"}


@router.get("/me")
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # TODO: Implement get current user
    return {"message": "Current user endpoint"}
