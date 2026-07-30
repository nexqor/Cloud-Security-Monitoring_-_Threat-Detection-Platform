from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import User
from app.services import auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Rate limiter instance (shared with main.py via state)
limiter = Limiter(key_func=get_remote_address)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, description="3–32 characters")
    password: str = Field(..., min_length=8, max_length=128, description="Minimum 8 characters")

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, hyphens, and underscores")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    username = auth_service.decode_access_token(token)
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return user


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user. Username: 3–32 chars (alphanumeric/hyphens/underscores). Password: min 8 chars."""
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username already taken")
    auth_service.create_user(db, payload.username, payload.password)
    token = auth_service.create_access_token(payload.username)
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Log in and receive a bearer token. Rate limited to 10 attempts per minute per IP."""
    user = auth_service.authenticate_user(db, form.username, form.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect username or password")
    token = auth_service.create_access_token(user.username)
    return TokenResponse(access_token=token)


@router.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "is_admin": current_user.is_admin,
        "created_at": current_user.created_at,
    }
