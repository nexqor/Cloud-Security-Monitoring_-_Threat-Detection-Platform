"""Rule: security group open to the internet on a sensitive port -> HIGH finding."""
from typing import Optional

RULE_ID = "OPEN_SECURITY_GROUP"
RISK_POINTS = 30

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}
OPEN_CIDR = "0.0.0.0/0"


def check(security_group: dict) -> Optional[dict]:
    """security_group: one item from app.aws.ec2.list_security_groups()"""
    for rule in security_group.get("ingress_rules", []):
        if rule.get("cidr") != OPEN_CIDR:
            continue
        from_port = rule.get("from_port")
        if from_port in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[from_port]
            return {
                "rule_id": RULE_ID,
                "title": f"Security group '{security_group['group_name']}' allows {service} from 0.0.0.0/0",
                "description": (
                    f"Port {from_port} ({service}) is open to the entire internet on "
                    f"{security_group['group_id']}. Restrict the source CIDR to a "
                    "known IP range, bastion host, or VPN."
                ),
                "severity": "HIGH",
                "risk_points": RISK_POINTS,
                "resource_type": "SecurityGroup",
                "resource_id": security_group["group_id"],
                "raw_event": None,
            }
    return None
