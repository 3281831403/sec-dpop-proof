"""DPoP proof binding and replay protection.

A proof is a compact, dot-separated three-segment value:

    base64url(JSON header) . base64url(JSON payload) . base64url(signature)

Cryptographic signature verification happens upstream.  This module owns the
binding rules that make a verified proof unusable anywhere except the request
it was minted for, and the replay rules that make it usable only once.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
from collections.abc import MutableMapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _is_finite_number(value: Any) -> bool:
    """Return True only for real, finite ints/floats (booleans excluded)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(
        value
    )


def _decode_b64url_json_object(segment: str) -> dict[str, Any]:
    """Decode an unpadded base64url segment into a JSON object."""
    if not segment or "=" in segment:
        raise ValueError("base64url segment must be non-empty and unpadded")
    if any(char not in _B64URL_ALPHABET for char in segment):
        raise ValueError("segment contains characters outside the base64url alphabet")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        decoded = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid base64url JSON segment") from exc
    if not isinstance(decoded, dict):
        raise ValueError("decoded segment must be a JSON object")
    return decoded


def split_proof(token: str) -> dict[str, Any]:
    """Split a compact proof into header, payload, and signature.

    The token must contain exactly three non-empty, dot-separated segments.
    Header and payload must be unpadded base64url segments that decode as
    UTF-8 JSON objects.  The signature segment is returned in its encoded
    form; its cryptography is checked upstream.

    Returns a new dictionary with exactly these keys:

        header     decoded header object
        payload    decoded payload object
        signature  the encoded signature segment as str

    Raise ValueError for a non-string token, a wrong segment count, an empty
    segment, invalid base64url, invalid JSON, or a header or payload that is
    not a JSON object.
    """
    if not isinstance(token, str):
        raise ValueError("proof token must be a string")
    segments = token.split(".")
    if len(segments) != 3 or any(segment == "" for segment in segments):
        raise ValueError("proof must have exactly three non-empty segments")
    header_segment, payload_segment, signature_segment = segments
    header = _decode_b64url_json_object(header_segment)
    payload = _decode_b64url_json_object(payload_segment)
    return {
        "header": header,
        "payload": payload,
        "signature": signature_segment,
    }


def normalize_url(url: str) -> str:
    """Return the canonical form of an absolute HTTP or HTTPS URL.

    Canonicalization rules:

    - lowercase the scheme and host;
    - remove port 80 for http and port 443 for https;
    - keep a non-default port;
    - drop the fragment;
    - keep the path exactly as supplied;
    - keep the query but sort its decoded name and value pairs by name and
      then by value, preserving duplicate names and blank values;
    - omit the query delimiter when the resulting query is empty.

    The result is scheme://host with the canonical port, path, and sorted
    query.  Raise ValueError for a non-string or non-absolute http or https
    URL, or for a URL without a host.  Do not perform DNS resolution.
    """
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("only absolute http and https URLs are supported")
    host = parts.hostname
    if not host:
        raise ValueError("URL must include a host")
    # parts.port raises ValueError for a malformed/out-of-range port.
    port = parts.port
    host = host.lower()
    if ":" in host:
        netloc = f"[{host}]"
    else:
        netloc = host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"

    pairs = parse_qsl(parts.query, keep_blank_values=True)
    pairs.sort(key=lambda pair: (pair[0], pair[1]))
    query = urlencode(pairs)

    canonical = f"{scheme}://{netloc}{parts.path}"
    if query:
        canonical = f"{canonical}?{query}"
    return canonical


def check_htm(payload: dict[str, Any], method: str) -> bool:
    """Check that the proof method matches the request method exactly.

    Comparison is case-insensitive: both values are normalized to uppercase.
    No trimming, prefix matching, or method aliasing is allowed.  Return False
    for missing, empty, or non-string values, and for a mismatch.
    """
    htm = payload.get("htm")
    if not isinstance(htm, str) or not htm:
        return False
    if not isinstance(method, str) or not method:
        return False
    return htm.upper() == method.upper()


def check_htu(payload: dict[str, Any], url: str) -> bool:
    """Check that the proof URI matches the request URI after normalization.

    Both the payload htu value and url must be normalized with normalize_url
    and then compared for exact string equality.  Any normalization failure
    is a failed check, not an exception.  Return False when htu is missing or
    is not a string.
    """
    htu = payload.get("htu")
    if not isinstance(htu, str) or not htu:
        return False
    try:
        return normalize_url(htu) == normalize_url(url)
    except ValueError:
        return False


def check_ath(payload: dict[str, Any], access_token: str) -> bool:
    """Check that the proof is bound to the presented access token.

    The required value is base64url without padding of SHA-256 over the UTF-8
    bytes of access_token.  The stored ath must equal that digest in full; a
    missing, empty, malformed, truncated, or extended digest fails.  Use a
    constant-time comparison.  Return False for an empty or non-string token.
    """
    if not isinstance(access_token, str) or access_token == "":
        return False
    ath = payload.get("ath")
    if not isinstance(ath, str) or ath == "":
        return False
    digest = base64.urlsafe_b64encode(
        hashlib.sha256(access_token.encode("utf-8")).digest()
    ).rstrip(b"=")
    # Full-length equality only: a prefix or an extended value cannot match,
    # and compare_digest in bytes never raises on non-ASCII input.
    return hmac.compare_digest(ath.encode("utf-8"), digest)


def check_jti(
    store: dict[str, Any],
    jti: str,
    now: float,
    ttl: float,
) -> bool:
    """Consume a one-time proof identifier and purge expired entries.

    store maps each previously seen jti to its expiry deadline as a number.
    Before looking up jti, delete every entry whose deadline is less than or
    equal to now, as well as entries whose deadline is not a finite number.
    If jti is still present, reject it.  Otherwise record its deadline as
    now plus ttl and accept it.

    Return True only for a fresh identifier.  Return False for an empty or
    non-string jti, a non-positive or non-finite ttl, a non-finite now, or a
    store that is not a mutable mapping.  Purging must happen even when the
    candidate jti itself is rejected.
    """
    if not isinstance(store, MutableMapping):
        return False
    if not _is_finite_number(now):
        return False

    # Purge first so expired/garbage entries are removed even when the
    # candidate jti or ttl is rejected below.
    for key in [
        key
        for key, deadline in store.items()
        if not _is_finite_number(deadline) or deadline <= now
    ]:
        del store[key]

    if not _is_finite_number(ttl) or ttl <= 0:
        return False
    if not isinstance(jti, str) or jti == "":
        return False
    if jti in store:
        return False
    store[jti] = now + ttl
    return True


def check_time(payload: dict[str, Any], now: float, window: float) -> bool:
    """Check the proof issue time against a directional, finite time window.

    The accepted interval is inclusive at both ends:

        now - window <= iat <= now

    A timestamp in the future is always rejected, including timestamps just
    one second ahead.  The window is not symmetric and must not be evaluated
    with an absolute difference.  window must be positive and finite; now and
    iat must be finite numbers.  Return False when the values are missing,
    non-numeric, boolean, non-finite, or outside the interval.
    """
    if not _is_finite_number(now) or not _is_finite_number(window) or window <= 0:
        return False
    iat = payload.get("iat")
    if not _is_finite_number(iat):
        return False
    return (now - window) <= iat <= now


def proof_batch(
    requests: list[dict[str, Any]],
    policy: dict[str, Any],
    now: float,
) -> dict[str, list[int]]:
    """Validate a batch of requests, each against its own proof.

    Each request is a mapping with these keys:

        proof         compact three-segment proof string
        method        HTTP method of this request
        url           request URI
        access_token  access token presented with this request

    policy is a mapping with these keys:

        jti_ttl       positive finite replay-cache lifetime
        clock_window  positive finite directional timestamp window
        jti_store     mutable mapping shared by the requests in the batch

    For every request, in original order, split that request's own proof and
    apply check_htm, check_htu, check_ath, check_time, and finally check_jti.
    A request is accepted only when every check passes.  Check jti last so a
    proof rejected for another binding reason does not consume its identifier.
    Any malformed request or proof rejects only that request; later requests
    must still be evaluated independently and must never inherit an earlier
    payload.

    Return exactly:

        {"accepted": [zero-based indices in input order],
         "rejected": [zero-based indices in input order]}
    """
    accepted: list[int] = []
    rejected: list[int] = []
    jti_store = policy.get("jti_store")
    jti_ttl = policy.get("jti_ttl")
    clock_window = policy.get("clock_window")

    for index, request in enumerate(requests):
        try:
            proof_token = request["proof"]
            method = request["method"]
            url = request["url"]
            access_token = request["access_token"]
            # Each request splits its own proof; nothing is carried over
            # from a previous iteration.
            parts = split_proof(proof_token)
        except (TypeError, KeyError, ValueError):
            rejected.append(index)
            continue

        payload = parts["payload"]
        # Short-circuiting keeps check_jti last, so a failed binding never
        # consumes the one-time identifier.
        is_valid = (
            check_htm(payload, method)
            and check_htu(payload, url)
            and check_ath(payload, access_token)
            and check_time(payload, now, clock_window)
            and check_jti(jti_store, payload.get("jti"), now, jti_ttl)
        )
        if is_valid:
            accepted.append(index)
        else:
            rejected.append(index)

    return {"accepted": accepted, "rejected": rejected}
