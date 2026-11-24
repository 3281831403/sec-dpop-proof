"""Behavioural tests for DPoP proof binding.

The ten bug tests are ordered exactly like the ten defects in README.md.
They must fail against the shipped stubs and pass only when the stubs are
implemented to the documented contract.
"""

import base64
import hashlib
import json
from typing import Any

from engine.dpop import proof as dpop

NOW = 1_700_000_000
METHOD = "POST"
URL = "https://rs.example/transfer?b=2&a=1"
ACCESS_TOKEN = "access-token-abc"
JTI = "jti-base"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _compact(payload: dict[str, Any], header: dict[str, Any] | None = None) -> str:
    if header is None:
        header = {"typ": "dpop+jwt", "alg": "ES256"}
    encoded_header = _b64url(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_payload = _b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_signature = _b64url(b"signature")
    return ".".join((encoded_header, encoded_payload, encoded_signature))


def _ath(access_token: str) -> str:
    digest = hashlib.sha256(access_token.encode("utf-8")).digest()
    return _b64url(digest)


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "htm": METHOD,
        "htu": URL,
        "ath": _ath(ACCESS_TOKEN),
        "jti": JTI,
        "iat": NOW,
    }
    payload.update(overrides)
    return payload


def _request(
    payload: dict[str, Any] | None = None,
    *,
    method: str = METHOD,
    url: str = URL,
    access_token: str = ACCESS_TOKEN,
    proof_token: str | None = None,
) -> dict[str, Any]:
    if proof_token is None:
        proof_token = _compact(_payload() if payload is None else payload)
    return {
        "proof": proof_token,
        "method": method,
        "url": url,
        "access_token": access_token,
    }


def _policy() -> dict[str, Any]:
    return {
        "jti_ttl": 300,
        "clock_window": 30,
        "jti_store": {},
    }


def test_valid_proof_is_accepted() -> None:
    result = dpop.proof_batch([_request(_payload())], _policy(), NOW)
    assert result == {"accepted": [0], "rejected": []}


def test_method_mismatch_is_rejected() -> None:
    result = dpop.proof_batch([_request(_payload(), method="GET")], _policy(), NOW)
    assert result == {"accepted": [], "rejected": [0]}


def test_url_mismatch_is_rejected() -> None:
    result = dpop.proof_batch(
        [_request(_payload(), url="https://rs.example/other")],
        _policy(),
        NOW,
    )
    assert result == {"accepted": [], "rejected": [0]}


def test_bug01_method_comparison_normalizes_case() -> None:
    payload = {"htm": "POST"}
    assert dpop.check_htm(payload, "post") is True
    assert dpop.check_htm(payload, "PoSt") is True
    assert dpop.check_htm(payload, "GET") is False


def test_bug02_default_port_is_removed() -> None:
    assert (
        dpop.normalize_url("https://RS.Example:443/a/b?x=1#frag")
        == "https://rs.example/a/b?x=1"
    )
    assert dpop.normalize_url("http://rs.example:80/a") == "http://rs.example/a"
    assert (
        dpop.normalize_url("https://rs.example:8443/a")
        == "https://rs.example:8443/a"
    )


def test_bug03_query_parameters_are_sorted() -> None:
    assert (
        dpop.normalize_url("https://rs.example/p?b=2&a=1")
        == "https://rs.example/p?a=1&b=2"
    )
    assert dpop.normalize_url("https://rs.example/p?b=2&a=1") == dpop.normalize_url(
        "https://rs.example/p?a=1&b=2"
    )


def test_bug04_missing_ath_is_rejected() -> None:
    assert dpop.check_ath({}, ACCESS_TOKEN) is False
    assert dpop.check_ath({"ath": ""}, ACCESS_TOKEN) is False
    assert dpop.check_ath({"ath": None}, ACCESS_TOKEN) is False


def test_bug05_short_ath_prefix_is_rejected() -> None:
    digest = _ath(ACCESS_TOKEN)
    assert dpop.check_ath({"ath": digest[:16]}, ACCESS_TOKEN) is False
    assert dpop.check_ath({"ath": digest[:-1]}, ACCESS_TOKEN) is False
    assert dpop.check_ath({"ath": digest + "A"}, ACCESS_TOKEN) is False
    assert dpop.check_ath({"ath": digest}, ACCESS_TOKEN) is True


def test_bug06_jti_replay_is_rejected() -> None:
    store: dict[str, Any] = {}
    assert dpop.check_jti(store, "jti-a", NOW, 300) is True
    assert dpop.check_jti(store, "jti-a", NOW + 1, 300) is False


def test_bug07_expired_jti_entries_are_purged() -> None:
    store: dict[str, Any] = {
        "expired": NOW - 1,
        "edge": NOW,
        "active": NOW + 1,
    }
    assert dpop.check_jti(store, "fresh", NOW, 60) is True
    assert "expired" not in store
    assert "edge" not in store
    assert "active" in store
    assert store["fresh"] == NOW + 60


def test_bug08_future_iat_is_rejected() -> None:
    assert dpop.check_time({"iat": NOW + 1}, NOW, 30) is False
    assert dpop.check_time({"iat": NOW + 30}, NOW, 30) is False
    assert dpop.check_time({"iat": NOW}, NOW, 30) is True


def test_bug09_time_window_has_direction() -> None:
    assert dpop.check_time({"iat": NOW - 30}, NOW, 30) is True
    assert dpop.check_time({"iat": NOW - 31}, NOW, 30) is False
    assert dpop.check_time({"iat": NOW + 29}, NOW, 30) is False
    assert dpop.check_time({"iat": NOW + 30}, NOW, 30) is False
    assert dpop.check_time({"iat": NOW}, NOW, float("inf")) is False


def test_bug10_batch_uses_each_own_payload() -> None:
    shared_payload = _payload(ath=_ath("token-b"), jti="jti-shared")
    first = _request(shared_payload, access_token="token-a")
    second = _request(
        shared_payload,
        access_token="token-b",
        proof_token="not-a-proof",
    )
    third = _request(_payload(jti="jti-third"))

    result = dpop.proof_batch([first, second, third], _policy(), NOW)
    assert result == {"accepted": [2], "rejected": [0, 1]}


def test_same_jti_second_use_is_rejected() -> None:
    first = _request(_payload(jti="jti-shared"))
    second = _request(_payload(jti="jti-shared"))

    result = dpop.proof_batch([first, second], _policy(), NOW)
    assert result == {"accepted": [0], "rejected": [1]}


def test_batches_match_independent_validation() -> None:
    requests = [
        _request(_payload(jti="jti-a")),
        _request(_payload(jti="jti-b"), method="GET"),
        _request(_payload(jti="jti-c")),
    ]

    batched = dpop.proof_batch(requests, _policy(), NOW)
    assert batched == {"accepted": [0, 2], "rejected": [1]}

    again = dpop.proof_batch(requests, _policy(), NOW)
    assert again == batched

    independent: dict[str, list[int]] = {"accepted": [], "rejected": []}
    for index, request in enumerate(requests):
        one = dpop.proof_batch([request], _policy(), NOW)
        assert set(one) == {"accepted", "rejected"}
        if one["accepted"] == [0]:
            assert one["rejected"] == []
            independent["accepted"].append(index)
        else:
            assert one["accepted"] == []
            assert one["rejected"] == [0]
            independent["rejected"].append(index)

    assert independent == batched