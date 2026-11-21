"""Runs against a real Vybase API:
    VYBASE_TEST_URL=http://localhost:8787 VYBASE_TEST_ADMIN=dev pytest
"""
import json
import os
import random
import urllib.request

import pytest

from vybase import Vybase, VybaseError

URL = os.environ.get("VYBASE_TEST_URL")
ADMIN = os.environ.get("VYBASE_TEST_ADMIN")
pytestmark = pytest.mark.skipif(not (URL and ADMIN), reason="set VYBASE_TEST_URL and VYBASE_TEST_ADMIN")
TAG = random.randint(0, 1 << 30)


@pytest.fixture(scope="module")
def project():
    req = urllib.request.Request(
        f"{URL}/v1/system/projects",
        data=json.dumps({"name": "python-sdk-test"}).encode(),
        headers={"authorization": f"Bearer {ADMIN}", "content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def test_verify_token_and_admin(project):
    pid = project["project"]["id"]
    app = Vybase(URL, publishable_key=project["keys"]["publishable"])
    server = Vybase(URL, secret_key=project["keys"]["secret"], project_id=pid)

    res = app.auth.sign_up(f"py{TAG}@example.com", "password-123", metadata={"plan": "free"})
    token = res["session"]["access_token"]

    claims = server.verify_token(token)
    assert claims.user_id == res["user"]["id"]
    assert claims.project_id == pid
    assert claims.email == f"py{TAG}@example.com"

    with pytest.raises(VybaseError) as e:
        server.verify_token(token[:-4] + "AAAA")
    assert e.value.code == "invalid_token"
    with pytest.raises(VybaseError):
        Vybase(URL, secret_key="x", project_id="prj_other").verify_token(token)

    found = server.admin.list_users(q=f"py{TAG}@")
    assert found["total"] == 1
    banned = server.admin.ban_user(res["user"]["id"])
    assert banned["banned"] is True
    with pytest.raises(VybaseError) as e:
        app.auth.sign_in_with_password(f"py{TAG}@example.com", "password-123")
    assert e.value.code == "user_banned"

    server.admin.delete_user(res["user"]["id"])
    with pytest.raises(VybaseError) as e:
        server.admin.get_user(res["user"]["id"])
    assert e.value.code == "user_not_found"


def test_errors_and_publishable_limits(project):
    app = Vybase(URL, publishable_key=project["keys"]["publishable"])
    assert app.admin is None
    app.auth.sign_up(f"dup{TAG}@example.com", "password-123")
    with pytest.raises(VybaseError) as e:
        app.auth.sign_up(f"dup{TAG}@example.com", "password-123")
    assert (e.value.code, e.value.status) == ("email_taken", 409)
    with pytest.raises(VybaseError) as e:
        Vybase("http://127.0.0.1:9", publishable_key="pk_x", timeout=2).auth.settings()
    assert e.value.code == "network_error"
