"""Request metadata that a caller controls and the application must not trust verbatim.

Two things arrive on every request as free text and both would otherwise reach a log line and
the audit chain:

* **the request path.** A URL a caller composes can carry anything — a patient name, a note, a
  search term — in a path segment. The application therefore logs the *route template* it
  matched (``/api/cases/{case_id}/documents``), never the URL that was asked for, and a request
  that matched no route is recorded as ``<unmatched>``. Design §7.5: "log only method, path
  template, status and duration".
* **a correlation id such as ``X-Request-ID``.** The application needs one to tie a log line to
  the audit row of the same request, but the value must be *its own*, not the caller's: a header
  value is not an identifier just because it is in an identifier's place. The id is generated
  server-side and returned to the caller in the ``X-Request-ID`` response header, so a client
  can still correlate without ever writing into a log or the audit chain.

Neither function sanitises a value into shape: a caller-supplied id is discarded, never trimmed
or escaped, so there is no string-replace path a crafted value can survive (INV-5).
"""

from __future__ import annotations

import uuid

from starlette.requests import Request

#: What a request that matched no route is called in a log line. Never the requested URL:
#: an unmatched path is exactly where an attacker (or a copy-pasted link) puts free text.
UNMATCHED_ROUTE = "<unmatched>"

#: The request-scoped attribute the middleware sets, read by the request-context dependency.
REQUEST_ID_STATE_ATTR = "cardioauth_request_id"


def new_request_id() -> str:
    """A fresh, opaque, PHI-free correlation id (32 hex characters, no structure)."""
    return uuid.uuid4().hex


def route_template(request: Request) -> str:
    """The matched route's template, or :data:`UNMATCHED_ROUTE`.

    Reads ``request.scope["route"].path`` — the pattern registered on the router, which contains
    parameter *names* and no caller-supplied value whatsoever.
    """
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    return template if isinstance(template, str) and template else UNMATCHED_ROUTE


def request_id_for(request: Request) -> str:
    """The correlation id of this request, generating one if the middleware did not set it.

    Called from the middleware (to log it and to answer with it) and from the request-context
    dependency (to put it on an audit row), so both always name the same id. A header value is
    never used — see the module docstring.
    """
    existing = getattr(request.state, REQUEST_ID_STATE_ATTR, None)
    if isinstance(existing, str) and existing:
        return existing
    generated = new_request_id()
    # ``setattr`` on ``request.state`` writes into ``scope["state"]``, which every ``Request``
    # object built for this scope shares. Two details matter here: attribute *assignment* must go
    # through ``setattr(state, name, value)`` — ``state.REQUEST_ID_STATE_ATTR = x`` would set a
    # literal attribute called "REQUEST_ID_STATE_ATTR" — and writing into ``request.state.__dict__``
    # would reach this Request's object only, while the dependency that puts the id on an audit row
    # builds its own Request for the same scope and would then generate a *second* id, leaving no
    # audit row correlatable with the log line.
    setattr(request.state, REQUEST_ID_STATE_ATTR, generated)
    return generated


__all__ = [
    "REQUEST_ID_STATE_ATTR",
    "UNMATCHED_ROUTE",
    "new_request_id",
    "request_id_for",
    "route_template",
]
