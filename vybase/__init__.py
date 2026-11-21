"""Vybase SDK for Python.

    from vybase import Vybase

    zyv = Vybase("https://auth.zyvraone.site", secret_key=os.environ["VYBASE_SECRET_KEY"])
    claims = zyv.verify_token(access_token)
    users = zyv.admin.list_users(q="gmail.com")
"""

from .client import AdminAPI, AuthAPI, TokenClaims, Vybase, VybaseError

__all__ = ["Vybase", "VybaseError", "TokenClaims", "AuthAPI", "AdminAPI"]
__version__ = "0.1.0"
