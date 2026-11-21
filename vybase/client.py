from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import jwt


class VybaseError(Exception):
    """Raised for every API error. Branch on ``code`` (stable), not on the message."""

    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


@dataclass
class TokenClaims:
    user_id: str
    project_id: str
    session_id: str
    email: Optional[str]
    phone: Optional[str]
    expires_at: int
    raw: Dict[str, Any] = field(repr=False)


class Vybase:
    """Client for one Vybase project.

    * ``secret_key`` (``sk_…``): server-side. Unlocks :attr:`admin`. Never ship it to browsers or apps.
    * ``publishable_key`` (``pk_…``): enough for :attr:`auth` sign-in calls.
    * ``project_id``: lets :meth:`verify_token` check the token's audience without a network call.
    """

    def __init__(
        self,
        url: str,
        *,
        secret_key: Optional[str] = None,
        publishable_key: Optional[str] = None,
        project_id: Optional[str] = None,
        timeout: float = 15.0,
    ):
        if not secret_key and not publishable_key:
            raise ValueError("Pass secret_key (server) or publishable_key.")
        self.url = url.rstrip("/")
        self.key = secret_key or publishable_key
        self.project_id = project_id
        self.timeout = timeout
        self._jwks = jwt.PyJWKClient(f"{self.url}/.well-known/jwks.json", cache_keys=True, lifespan=600)
        self._lock = threading.Lock()
        self.auth = AuthAPI(self)
        self.admin = AdminAPI(self) if secret_key else None

    # -- transport ---------------------------------------------------------------------------

    def request(self, method: str, path: str, body: Optional[dict] = None, token: Optional[str] = None) -> Any:
        headers = {"x-zyvraon-key": self.key or "", "accept": "application/json", "user-agent": "vybase-python/0.1"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["content-type"] = "application/json"
        if token:
            headers["authorization"] = f"Bearer {token}"
        req = urllib.request.Request(f"{self.url}{path}", data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                raw = res.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read() or b"{}").get("error", {})
            except ValueError:
                err = {}
            raise VybaseError(err.get("code", "http_error"), err.get("message", e.reason), e.code) from None
        except urllib.error.URLError as e:
            raise VybaseError("network_error", str(e.reason), 0) from None

    # -- tokens ------------------------------------------------------------------------------

    def verify_token(self, access_token: str) -> TokenClaims:
        """Verifies a user's access token offline (ES256, cached JWKS). Raises VybaseError("invalid_token")."""
        try:
            key = self._jwks.get_signing_key_from_jwt(access_token)
            claims = jwt.decode(
                access_token,
                key.key,
                algorithms=["ES256"],
                issuer=self.url,
                audience=self.project_id,
                options={"verify_aud": self.project_id is not None, "require": ["exp", "sub", "aud"]},
            )
        except jwt.PyJWTError as e:
            raise VybaseError("invalid_token", str(e), 401) from None
        if not claims.get("pid") or not claims.get("sid") or claims.get("aud") != claims.get("pid"):
            raise VybaseError("invalid_token", "Not a Vybase project access token.", 401)
        return TokenClaims(
            user_id=claims["sub"],
            project_id=claims["pid"],
            session_id=claims["sid"],
            email=claims.get("email"),
            phone=claims.get("phone"),
            expires_at=int(claims["exp"]),
            raw=claims,
        )


class AuthAPI:
    """End-user auth calls. Returns the API's JSON: ``{"user": …, "session": …}``."""

    def __init__(self, client: Vybase):
        self._c = client

    def settings(self) -> dict:
        return self._c.request("GET", "/v1/auth/settings")

    def sign_up(self, email: str, password: str, metadata: Optional[dict] = None, redirect_to: Optional[str] = None) -> dict:
        body: Dict[str, Any] = {"email": email, "password": password}
        if metadata is not None:
            body["metadata"] = metadata
        if redirect_to:
            body["redirect_to"] = redirect_to
        return self._c.request("POST", "/v1/auth/signup", body)

    def sign_in_with_password(self, email: str, password: str) -> dict:
        return self._c.request("POST", "/v1/auth/login", {"email": email, "password": password})

    def send_otp(self, *, email: Optional[str] = None, phone: Optional[str] = None, channel: str = "sms") -> dict:
        if (email is None) == (phone is None):
            raise ValueError("Pass exactly one of email or phone.")
        return self._c.request("POST", "/v1/auth/otp/send", {"email": email} if email else {"phone": phone, "channel": channel})

    def verify_otp(self, code: str, *, email: Optional[str] = None, phone: Optional[str] = None) -> dict:
        if (email is None) == (phone is None):
            raise ValueError("Pass exactly one of email or phone.")
        return self._c.request("POST", "/v1/auth/otp/verify", {"email": email, "code": code} if email else {"phone": phone, "code": code})

    def refresh(self, refresh_token: str) -> dict:
        return self._c.request("POST", "/v1/auth/refresh", {"refresh_token": refresh_token})

    def get_user(self, access_token: str) -> dict:
        return self._c.request("GET", "/v1/auth/user", token=access_token)["user"]

    def sign_out(self, access_token: str, everywhere: bool = False) -> None:
        self._c.request("POST", "/v1/auth/logout" + ("?scope=global" if everywhere else ""), token=access_token)

    def reset_password_for_email(self, email: str, redirect_to: Optional[str] = None) -> None:
        self._c.request("POST", "/v1/auth/recover", {"email": email, **({"redirect_to": redirect_to} if redirect_to else {})})


class AdminAPI:
    """User management with the secret key."""

    def __init__(self, client: Vybase):
        self._c = client

    def list_users(self, q: Optional[str] = None, page: int = 1, per_page: int = 50) -> dict:
        qs = {"page": page, "per_page": per_page}
        if q:
            qs["q"] = q
        return self._c.request("GET", f"/v1/auth/admin/users?{urllib.parse.urlencode(qs)}")

    def get_user(self, user_id: str) -> dict:
        return self._c.request("GET", f"/v1/auth/admin/users/{urllib.parse.quote(user_id)}")["user"]

    def create_user(
        self,
        *,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        password: Optional[str] = None,
        email_confirmed: bool = False,
        phone_confirmed: bool = False,
        metadata: Optional[dict] = None,
    ) -> dict:
        body = {k: v for k, v in dict(email=email, phone=phone, password=password, metadata=metadata).items() if v is not None}
        body.update(email_confirmed=email_confirmed, phone_confirmed=phone_confirmed)
        return self._c.request("POST", "/v1/auth/admin/users", body)["user"]

    def update_user(self, user_id: str, **changes: Any) -> dict:
        """changes: password, metadata, replace_metadata, banned, email_confirmed."""
        return self._c.request("PATCH", f"/v1/auth/admin/users/{urllib.parse.quote(user_id)}", changes)["user"]

    def ban_user(self, user_id: str) -> dict:
        return self.update_user(user_id, banned=True)

    def unban_user(self, user_id: str) -> dict:
        return self.update_user(user_id, banned=False)

    def delete_user(self, user_id: str) -> None:
        self._c.request("DELETE", f"/v1/auth/admin/users/{urllib.parse.quote(user_id)}")

    def sign_out_user(self, user_id: str) -> None:
        self._c.request("POST", f"/v1/auth/admin/users/{urllib.parse.quote(user_id)}/logout")
