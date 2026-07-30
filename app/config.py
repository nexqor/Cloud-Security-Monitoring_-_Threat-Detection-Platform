"""
Central configuration for CloudShield.

All AWS credentials and app secrets are loaded from environment variables
(via a .env file in dev, or real environment variables / IAM roles in prod).
Nothing is ever hardcoded here.
"""
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    app_env: str = "development"
    secret_key: str = "dev-secret-change-me"
    access_token_expire_minutes: int = 60

    # --- Database ---
    database_url: str = "sqlite:///./cloudshield.db"

    # --- AWS ---
    # If access_key/secret are blank, aws_service falls back to the default
    # boto3 credential chain (profile, instance role, env vars set outside .env, etc.)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_region: str = "ap-south-1"

    # --- Alerting ---
    sns_topic_arn: Optional[str] = None
    alert_email_from: Optional[str] = None
    alert_email_to: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton — import this, don't instantiate Settings() directly."""
    return Settings()
