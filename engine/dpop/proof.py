"""DPoP proof binding and replay protection.

A proof is a compact, dot-separated three-segment value:

    base64url(JSON header) . base64url(JSON payload) . base64url(signature)

Cryptographic signature verification happens upstream.  This module owns the
binding rules that make a verified proof unusable anywhere except the request
it was minted for, and the replay rules that make it usable only once.

Every public function is an intentional stub for the exercise.
"""

from __future__ import annotations

from typing import Any


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
    raise NotImplementedError


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
    raise NotImplementedError


def check_htm(payload: dict[str, Any], method: str) -> bool:
    """Check that the proof method matches the request method exactly.

    Comparison is case-insensitive: both values are normalized to uppercase.
    No trimming, prefix matching, or method aliasing is allowed.  Return False
    for missing, empty, or non-string values, and for a mismatch.
    """
    raise NotImplementedError


def check_htu(payload: dict[str, Any], url: str) -> bool:
    """Check that the proof URI matches the request URI after normalization.

    Both the payload htu value and url must be normalized with normalize_url
    and then compared for exact string equality.  Any normalization failure
    is a failed check, not an exception.  Return False when htu is missing or
    is not a string.
    """
    raise NotImplementedError


def check_ath(payload: dict[str, Any], access_token: str) -> bool:
    """Check that the proof is bound to the presented access token.

    The required value is base64url without padding of SHA-256 over the UTF-8
    bytes of access_token.  The stored ath must equal that digest in full; a
    missing, empty, malformed, truncated, or extended digest fails.  Use a
    constant-time comparison.  Return False for an empty or non-string token.
    """
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError