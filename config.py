"""Server configuration — all from environment variables."""

import os

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/yiban.db")

# JWT
JWT_SECRET = os.getenv("JWT_SECRET", "")  # 生产环境必须设置！否则启动时报错
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30

# Encryption key for stored yiban credentials (Fernet)
# Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
CREDENTIAL_ENCRYPTION_KEY = os.getenv("CREDENTIAL_ENCRYPTION_KEY", "")

# Check-in schedule
CHECKIN_HOUR = int(os.getenv("CHECKIN_HOUR", "21"))
CHECKIN_MINUTE = int(os.getenv("CHECKIN_MINUTE", "30"))

# Push notification
PUSH_ENABLED = os.getenv("PUSH_ENABLED", "true").lower() == "true"

# Subscription
# In production, set this to your 爱发电 webhook secret
AFDIAN_TOKEN = os.getenv("AFDIAN_TOKEN", "")
