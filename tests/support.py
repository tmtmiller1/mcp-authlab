"""Shared helpers: start fixtures, log in without a browser, scan in-process."""

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any

from mcp_authlab import checks, fixture, oauthclient
from mcp_authlab.fixture import FixtureState


class FixtureCase(unittest.TestCase):
    def setUp(self) -> None:
        # Keep every test's tokens out of the real ~/.config store.
        self._tmp = tempfile.TemporaryDirectory()
        self._old = os.environ.get("MCP_AUTHLAB_TOKENS")
        os.environ["MCP_AUTHLAB_TOKENS"] = os.path.join(self._tmp.name, "tokens.json")

    def tearDown(self) -> None:
        if self._old is None:
            os.environ.pop("MCP_AUTHLAB_TOKENS", None)
        else:
            os.environ["MCP_AUTHLAB_TOKENS"] = self._old
        self._tmp.cleanup()

    def start(self, name: str, flags: list[str] | None = None, auto_consent: bool = True) -> FixtureState:
        profile = fixture.profile_from_args(name, flags or [])
        srv, state = fixture.serve(profile, auto_consent=auto_consent)
        fixture.start(srv)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return state

    def login(self, state: FixtureState, **kw: Any) -> oauthclient.LoginOutcome:
        if state.profile.no_registration:
            kw.setdefault("client_id", "test-client")
        lg = oauthclient.Login(state.public_url, no_browser=True, timeout=5, http_timeout=5, log=lambda _s: None, **kw)
        self.last_login = lg
        return lg.run()

    def scan(self, name: str, flags: list[str] | None = None, mode: str = "login", **kw: Any) -> dict[str, Any]:
        """mode: 'login' runs the OAuth flow first; 'dev' mints tokens directly; 'none' scans unauthenticated."""
        state = self.start(name, flags)
        if mode == "login":
            stored = self.login(state).to_store()
            return checks.run(state.public_url, stored=stored, timeout=5, **kw)
        if mode == "dev":
            return checks.run(
                state.public_url,
                token=state.mint(),
                foreign_token=state.mint(aud="https://other.example/mcp"),
                timeout=5,
                **kw,
            )
        return checks.run(state.public_url, timeout=5, **kw)


def flagged(data: dict[str, Any]) -> set[str]:
    return {r["id"] for r in data["results"] if r["status"] in ("fail", "warn") and r["id"] != "TLS-01"}


def by_id(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in data["results"]}


def statuses(data: dict[str, Any], status: str) -> set[str]:
    return {r["id"] for r in data["results"] if r["status"] == status}
