"""Well-known URL construction per RFC 9728 (protected resource) and RFC 8414 / OIDC Discovery (authorization
server)."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonical(url: str) -> str:
    """Canonical resource identifier per RFC 8707 section 2 as used by MCP.

    Lowercase scheme and host, no default port, no fragment, no trailing slash.
    """
    p = urlsplit(url.strip())
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    netloc = host if (port is None or _DEFAULT_PORTS.get(scheme) == port) else f"{host}:{port}"
    path = p.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, p.query, ""))


def is_loopback(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.startswith("127.")


def protected_resource_metadata_urls(resource: str) -> list[str]:
    """RFC 9728 section 3.1: path-aware location first, then the root fallback many servers use."""
    p = urlsplit(resource)
    origin = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    urls = []
    if path:
        urls.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    urls.append(f"{origin}/.well-known/oauth-protected-resource")
    return urls


def authorization_server_metadata_urls(issuer: str) -> list[tuple[str, str]]:
    """Discovery locations in the priority order the MCP spec gives clients.

    Returns (kind, url) pairs where kind is 'rfc8414' or 'oidc'.
    """
    p = urlsplit(issuer)
    origin = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    if path:
        return [
            ("rfc8414", f"{origin}/.well-known/oauth-authorization-server{path}"),
            ("oidc", f"{origin}/.well-known/openid-configuration{path}"),
            ("oidc", f"{origin}{path}/.well-known/openid-configuration"),
        ]
    return [
        ("rfc8414", f"{origin}/.well-known/oauth-authorization-server"),
        ("oidc", f"{origin}/.well-known/openid-configuration"),
    ]
