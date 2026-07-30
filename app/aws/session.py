"""
Shared boto3 session factory.

If AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are set in the environment (.env),
they're used explicitly. Otherwise this falls back to the default boto3
credential chain (profile, instance role, SSO, env vars set outside .env).

Never log or print credentials from this module.
"""
import boto3

from app.config import get_settings

settings = get_settings()


def get_session() -> boto3.Session:
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        return boto3.Session(
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            aws_session_token=settings.aws_session_token or None,
            region_name=settings.aws_region,
        )
    # Falls back to ~/.aws/credentials, instance role, SSO, etc.
    return boto3.Session(region_name=settings.aws_region)


def get_client(service_name: str):
    return get_session().client(service_name)


def get_resource(service_name: str):
    return get_session().resource(service_name)
