from app.detection import root_login, public_bucket, open_security_group, iam_admin, access_key


def test_root_login_fires_on_root_console_login():
    event = {"event_name": "ConsoleLogin", "username": "Root", "event_id": "evt-1", "raw": "{}"}
    finding = root_login.check(event)
    assert finding is not None
    assert finding["rule_id"] == "ROOT_LOGIN"
    assert finding["severity"] == "CRITICAL"


def test_root_login_ignores_non_root_login():
    event = {"event_name": "ConsoleLogin", "username": "alice", "event_id": "evt-2"}
    assert root_login.check(event) is None


def test_root_login_ignores_other_events():
    event = {"event_name": "CreateUser", "username": "Root", "event_id": "evt-3"}
    assert root_login.check(event) is None


def test_public_bucket_fires_when_public():
    bucket = {"name": "my-public-bucket", "is_public": True}
    finding = public_bucket.check(bucket)
    assert finding is not None
    assert finding["resource_id"] == "my-public-bucket"
    assert finding["severity"] == "MEDIUM"


def test_public_bucket_ignores_private():
    bucket = {"name": "my-private-bucket", "is_public": False}
    assert public_bucket.check(bucket) is None


def test_open_security_group_fires_on_open_ssh():
    sg = {
        "group_id": "sg-123",
        "group_name": "web-sg",
        "ingress_rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0"}],
    }
    finding = open_security_group.check(sg)
    assert finding is not None
    assert finding["severity"] == "HIGH"
    assert "SSH" in finding["title"]


def test_open_security_group_ignores_restricted_cidr():
    sg = {
        "group_id": "sg-456",
        "group_name": "web-sg",
        "ingress_rules": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "10.0.0.0/8"}],
    }
    assert open_security_group.check(sg) is None


def test_open_security_group_ignores_non_sensitive_port():
    sg = {
        "group_id": "sg-789",
        "group_name": "web-sg",
        "ingress_rules": [{"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0"}],
    }
    assert open_security_group.check(sg) is None


def test_iam_admin_fires_for_admin_user():
    user = {"username": "bob", "arn": "arn:aws:iam::123:user/bob", "is_admin": True}
    finding = iam_admin.check(user)
    assert finding is not None
    assert finding["severity"] == "CRITICAL"


def test_iam_admin_ignores_non_admin():
    user = {"username": "carol", "arn": "arn:aws:iam::123:user/carol", "is_admin": False}
    assert iam_admin.check(user) is None


def test_access_key_fires_when_stale():
    user = {
        "username": "dave",
        "access_keys": [{"access_key_id": "AKIA123", "status": "Active", "created": "2023-01-01 00:00:00"}],
    }
    finding = access_key.check(user)
    assert finding is not None
    assert finding["rule_id"] == "STALE_ACCESS_KEY"


def test_access_key_ignores_fresh_key():
    import datetime as dt
    recent = (dt.datetime.utcnow() - dt.timedelta(days=5)).isoformat(sep=" ")
    user = {"username": "eve", "access_keys": [{"access_key_id": "AKIA456", "status": "Active", "created": recent}]}
    assert access_key.check(user) is None


def test_access_key_ignores_inactive_key():
    user = {
        "username": "frank",
        "access_keys": [{"access_key_id": "AKIA789", "status": "Inactive", "created": "2020-01-01 00:00:00"}],
    }
    assert access_key.check(user) is None
