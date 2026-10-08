"""Multi-folder extraction must survive SDK response-model validation errors (no network).

pan-scm-sdk's LogForwardingProfileResponseModel forbids extra fields, so a
match-list entry carrying an auto-tag ``actions`` block makes
``log_forwarding_profile.list()`` raise for every folder. The multi-folder
helper used to record an error per folder and back up zero profiles; it now
re-lists that folder over raw REST, as the single-folder helper already did.
"""

from __future__ import annotations

from typing import Any

from scm_harbourmaster_mcp.audit import extractor

PROFILE = {
    "id": "lfp-1",
    "name": "Example Profile",
    "folder": "All",
    "match_list": [
        {"name": "threat-logs", "log_type": "threat", "filter": "All Logs"},
        {
            "name": "auto-tag",
            "log_type": "threat",
            "filter": "All Logs",
            "actions": [
                {
                    "name": "tag-src",
                    "type": {
                        "tagging": {
                            "target": "source-address",
                            "action": "add-tag",
                            "tags": ["example-tag"],
                        }
                    },
                }
            ],
        },
    ],
}

_VALIDATION_ERROR = (
    "1 validation error for LogForwardingProfileResponseModel\n"
    "match_list.1.actions\n  Extra inputs are not permitted [type=extra_forbidden]"
)


class _Resp:
    def __init__(self, body: Any) -> None:
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self._body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._body


class _Session:
    def __init__(self) -> None:
        self.lfp_calls: list[dict[str, Any]] = []

    def get(self, url: str, params: Any = None, timeout: Any = None, **_: Any) -> _Resp:
        if url.endswith("/log-forwarding-profiles"):
            self.lfp_calls.append(dict(params or {}))
            return _Resp({"data": [PROFILE]})
        return _Resp({"data": []})


class _Resource:
    ENDPOINT = "/config/objects/v1/log-forwarding-profiles"

    def __init__(self, error: str | None = None) -> None:
        self._error = error

    def list(self, **_: Any) -> list[Any]:
        if self._error:
            raise ValueError(self._error)
        return []


class _Client:
    def __init__(self) -> None:
        self.session = _Session()
        self.log_forwarding_profile = _Resource(_VALIDATION_ERROR)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return _Resource()


def test_log_forwarding_profiles_fall_back_to_rest_on_validation_error():
    client = _Client()

    snap = extractor.extract_snapshot(client, "Prisma Access", "1234567890", fresh=True)

    # Same profile from every folder, de-duplicated by id, with the auto-tag entry intact.
    assert [p["name"] for p in snap.log_forwarding_profiles] == ["Example Profile"]
    assert snap.log_forwarding_profiles[0]["match_list"][1]["actions"][0]["name"] == "tag-src"
    assert not [e for e in snap.extraction_errors if "log_forwarding_profile" in e]
    # One REST re-list per folder the SDK failed on, each scoped to that folder.
    assert {c["folder"] for c in client.session.lfp_calls} == {
        "Prisma Access",
        "Remote Networks",
        "Mobile Users",
        "Service Connections",
    }


def test_non_validation_errors_are_still_recorded():
    client = _Client()
    client.log_forwarding_profile = _Resource("403 Access denied")

    snap = extractor.extract_snapshot(client, "Prisma Access", "1234567890", fresh=True)

    assert snap.log_forwarding_profiles == []
    assert client.session.lfp_calls == []
    assert [e for e in snap.extraction_errors if e.startswith("log_forwarding_profile (")]
