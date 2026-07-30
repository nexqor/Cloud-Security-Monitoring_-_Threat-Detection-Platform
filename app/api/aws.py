from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.services import aws_service

router = APIRouter(prefix="/api/aws", tags=["aws"], dependencies=[Depends(get_current_user)])


@router.get("/ec2")
def ec2_instances():
    return aws_service.get_resource_inventory()["ec2_instances"]


@router.get("/s3")
def s3_buckets():
    return aws_service.get_resource_inventory()["s3_buckets"]


@router.get("/iam-users")
def iam_users():
    return aws_service.get_resource_inventory()["iam_users"]


@router.get("/security-groups")
def security_groups():
    return aws_service.get_resource_inventory()["security_groups"]


@router.get("/vpcs")
def vpcs():
    return aws_service.get_resource_inventory()["vpcs"]


@router.get("/inventory")
def full_inventory():
    """Everything in one call — used by the scan job, exposed here for debugging."""
    return aws_service.get_resource_inventory()


@router.get("/cloudtrail")
def cloudtrail_events(lookback_hours: int = 24):
    return aws_service.get_recent_cloudtrail_events(lookback_hours=lookback_hours)
