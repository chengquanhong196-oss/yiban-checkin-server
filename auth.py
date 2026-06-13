"""JWT authentication + credential encryption."""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_DAYS, CREDENTIAL_ENCRYPTION_KEY
from models import User, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
fernet = Fernet(CREDENTIAL_ENCRYPTION_KEY.encode()) if CREDENTIAL_ENCRYPTION_KEY else None


# ============================================================
# Password hashing
# ============================================================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ============================================================
# JWT
# ============================================================

def create_access_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI dependency — extracts and validates JWT, returns User."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
    except (JWTError, ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="无效的登录凭证")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户不存在")
    return user


# ============================================================
# Credential encryption (Fernet)
# ============================================================

def encrypt_config(config: dict) -> str:
    """Encrypt yiban config dict → base64 string."""
    if not fernet:
        raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY not set")
    raw = json.dumps(config, ensure_ascii=False).encode()
    return fernet.encrypt(raw).decode()


def decrypt_config(encrypted: Optional[str]) -> dict:
    """Decrypt yiban config → dict, or empty dict."""
    if not encrypted or not fernet:
        return {}
    return json.loads(fernet.decrypt(encrypted.encode()).decode())


def subscription_active(user: User) -> bool:
    """Check if user has an active paid subscription."""
    if user.tier in ("monthly", "yearly", "lifetime"):
        if user.tier == "lifetime":
            return True
        if user.expires_at and user.expires_at > datetime.now(timezone.utc):
            return True
        # Expired — downgrade
        user.tier = "free"
        user.expires_at = None
    return False
