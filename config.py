import os

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "SUPER_SECRET_PRIMETRADE_KEY_CHANGE_THIS_IN_PROD")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite:///./primetrade.db"

settings = Settings()