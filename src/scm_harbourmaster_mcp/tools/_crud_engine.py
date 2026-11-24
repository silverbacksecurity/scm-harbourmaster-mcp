"""Type-agnostic CRUD helpers shared by the SCM write tools.

The body-schema DSL (``B``/``Int``/``S``/``L``/``Obj``/``X``), the validator
that walks it, and the merge/diff/read-back helpers.  Extracted from
``security_profile`` so ``scm_object`` can reuse them unchanged.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from .threat_profile import is_blank, pair_named

_SCOPE_KEYS = ("folder", "snippet", "device")

Node = tuple[Any, ...]


def B() -> Node:  # noqa: N802 - schema constructors read as type names
    return ("b",)


def Int(lo: int | None = None, hi: int | None = None) -> Node:
    return ("i", lo, hi)


def S(
    enum: tuple[str, ...] | None = None, max_len: int | None = None, pattern: str | None = None
) -> Node:
    return ("s", enum, max_len, pattern)


def L(item: Node) -> Node:
    return ("l", item)


def Obj(fields: dict[str, Node], required: tuple[str, ...] = ()) -> Node:
    return ("o", fields, required)


def X(fields: dict[str, Node]) -> Node:
    """An object with exactly one of *fields* set (replaced whole on update)."""
    return ("x", fields)


def _bools(*names: str) -> dict[str, Node]:
    return {n: B() for n in names}


def _check(
    node: Node, value: Any, path: str, errs: list[str], *, strict: bool, null_ok: bool
) -> None:
    """Append every problem with *value* against *node* (type, enum, keys).

    ``strict`` enforces required keys (create); ``null_ok`` lets None through
    (update uses it to unset a key).
    """
    if value is None:
        if not null_ok:
            errs.append(f"{path}: null is only allowed on update (it removes the key)")
        return
    kind = node[0]
    if kind == "b":
        if not isinstance(value, bool):
            errs.append(f"{path}: must be true/false")
    elif kind == "i":
        if isinstance(value, bool) or not isinstance(value, int):
            errs.append(f"{path}: must be an integer")
        else:
            _, lo, hi = node
            if (lo is not None and value < lo) or (hi is not None and value > hi):
                errs.append(f"{path}: {value} outside {lo}..{hi}")
    elif kind == "s":
        _, enum, max_len, pattern = node
        if not isinstance(value, str):
            errs.append(f"{path}: must be a string")
        elif enum is not None and value not in enum:
            errs.append(f"{path}: {value!r} not one of {list(enum)}")
        elif max_len is not None and len(value) > max_len:
            errs.append(f"{path}: longer than {max_len} characters")
        elif pattern is not None and not re.match(pattern, value):
            errs.append(f"{path}: {value!r} does not match {pattern}")
    elif kind == "l":
        if not isinstance(value, list):
            errs.append(f"{path}: must be a list")
            return
        for i, item in enumerate(value):
            _check(node[1], item, f"{path}[{i}]", errs, strict=strict, null_ok=False)
    elif kind == "o":
        _check_object(node[1], node[2], value, path, errs, strict=strict, null_ok=null_ok)
    elif kind == "x":
        if not isinstance(value, dict):
            errs.append(f"{path}: must be an object")
            return
        keys = sorted(value)
        unknown = [k for k in keys if k not in node[1]]
        if unknown:
            errs.append(f"{path}: unknown keys {unknown}; allowed {sorted(node[1])}")
        elif len(keys) != 1:
            errs.append(f"{path}: set exactly one of {sorted(node[1])}")
        else:
            _check(
                node[1][keys[0]],
                value[keys[0]],
                f"{path}.{keys[0]}",
                errs,
                strict=strict,
                null_ok=False,
            )


def _check_object(
    fields: dict[str, Node],
    required: tuple[str, ...],
    value: Any,
    path: str,
    errs: list[str],
    *,
    strict: bool,
    null_ok: bool,
) -> None:
    if not isinstance(value, dict):
        errs.append(f"{path}: must be an object")
        return
    unknown = sorted(set(value) - set(fields))
    if unknown:
        errs.append(f"{path}: unknown keys {unknown}; allowed {sorted(fields)}")
    if strict:
        errs.extend(f"{path}.{k}: required" for k in required if value.get(k) is None)
    for key, sub in value.items():
        if key in fields:
            _check(fields[key], sub, f"{path}.{key}", errs, strict=strict, null_ok=null_ok)


def _merge(base: dict[str, Any], delta: dict[str, Any], fields: dict[str, Node]) -> dict[str, Any]:
    """*delta* over *base*: objects merge by key, lists/scalars/one-of objects
    replace, None removes the key."""
    out = copy.deepcopy(base)
    for key, value in delta.items():
        node = fields.get(key)
        if value is None:
            out.pop(key, None)
        elif (
            node is not None
            and node[0] == "o"
            and isinstance(value, dict)
            and isinstance(out.get(key), dict)
        ):
            out[key] = _merge(out[key], value, node[1])
        else:
            out[key] = copy.deepcopy(value)
    return out


def _covers(stored: Any, expected: Any) -> bool:
    """True when *stored* holds everything in *expected* (extra stored keys,
    such as server defaults, are fine).  Lists of named dicts compare by name
    (order-insensitive); ''/None/missing are equal."""
    if isinstance(expected, dict):
        return isinstance(stored, dict) and all(
            is_blank(stored.get(k)) if is_blank(v) else _covers(stored.get(k), v)
            for k, v in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(stored, list) or len(stored) != len(expected):
            return False
        pairs = pair_named(stored, expected)
        if pairs is not None:
            return all(_covers(s, e) for s, e in pairs)
        if all(not isinstance(e, dict | list) for e in expected):
            return sorted(map(str, stored)) == sorted(map(str, expected))
        return all(_covers(s, e) for s, e in zip(stored, expected, strict=True))
    return stored == expected or (is_blank(stored) and is_blank(expected))


def _diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(k for k in set(before) & set(after) if before[k] != after[k]),
    }


def _scope(folder: str, snippet: str, device: str) -> tuple[dict[str, str], str]:
    given = {
        k: v.strip() for k, v in (("folder", folder), ("snippet", snippet), ("device", device))
    }
    given = {k: v for k, v in given.items() if v}
    if len(given) > 1:
        return {}, "pass only one of folder, snippet or device"
    return given, ""


def _items(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        items = body["data"]
    elif isinstance(body, list):
        items = body
    else:
        items = [body]
    return [i for i in items if isinstance(i, dict)]
