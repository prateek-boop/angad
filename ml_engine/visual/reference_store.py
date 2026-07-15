"""Validated, deterministic reference pHash storage for known brand pages."""

from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Any

import config
from ml_engine.visual.perceptual_hash import hash_distance, parse_hash, serialize_hash

STORE_PATH = os.path.join(config.DATA_DIR, "visual_reference_store.json")
MAX_STORE_BYTES = 1 * 1024 * 1024
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ReferenceStoreError(ValueError):
    """Raised when a reference store is malformed or cannot be persisted."""


def normalize_brand_domain(brand_domain: str) -> str:
    """Canonicalize a DNS domain used as a reference key."""
    if not isinstance(brand_domain, str):
        raise TypeError("brand_domain must be a string")
    candidate = brand_domain.strip().rstrip(".").lower()
    if not candidate or any(
        token in candidate for token in ("://", "/", "?", "#", "@", ":")
    ):
        raise ValueError("brand_domain must be a bare DNS domain")
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("brand_domain is not a valid IDNA domain") from exc
    if len(ascii_domain) > 253:
        raise ValueError("brand_domain is too long")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("brand_domain must be a valid registrable-style DNS domain")
    return ascii_domain


def _validate_threshold(threshold: int) -> int:
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise TypeError("visual match threshold must be an integer")
    if not 0 <= threshold <= 64:
        raise ValueError("visual match threshold must be between 0 and 64")
    return threshold


class ReferenceStore:
    """A small JSON-backed mapping of normalized brand domains to pHashes.

    Writes are atomic, reads reject malformed content, and nearest-match ties
    are resolved lexicographically so results do not depend on insertion order.
    ``add`` mutates memory only; call ``save`` to persist a batch of changes.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = os.fspath(path or STORE_PATH)
        self._entries: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        if not os.path.exists(self.path):
            return {}
        try:
            if os.path.getsize(self.path) > MAX_STORE_BYTES:
                raise ReferenceStoreError(
                    "visual reference store exceeds its size limit"
                )
            with open(self.path, encoding="utf-8") as handle:
                raw_entries = json.load(handle)
        except ReferenceStoreError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReferenceStoreError(
                f"could not read visual reference store: {exc}"
            ) from exc

        if not isinstance(raw_entries, dict):
            raise ReferenceStoreError(
                "visual reference store root must be a JSON object"
            )

        entries: dict[str, str] = {}
        try:
            for raw_domain, raw_hash in raw_entries.items():
                domain = normalize_brand_domain(raw_domain)
                if domain in entries:
                    raise ReferenceStoreError(
                        f"duplicate normalized brand domain: {domain}"
                    )
                entries[domain] = serialize_hash(raw_hash)
        except ReferenceStoreError:
            raise
        except (TypeError, ValueError) as exc:
            raise ReferenceStoreError(f"invalid visual reference entry: {exc}") from exc
        return entries

    def save(self) -> None:
        target = os.path.abspath(self.path)
        directory = os.path.dirname(target)
        try:
            os.makedirs(directory, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                dir=directory, prefix=".visual-reference-", suffix=".json", text=True
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(self._entries, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except OSError as exc:
            raise ReferenceStoreError(
                f"could not save visual reference store: {exc}"
            ) from exc

    def add(self, brand_domain: str, phash: Any) -> None:
        self._entries[normalize_brand_domain(brand_domain)] = serialize_hash(phash)

    def remove(self, brand_domain: str) -> bool:
        """Remove a brand reference and return whether it existed."""
        return self._entries.pop(normalize_brand_domain(brand_domain), None) is not None

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def domains(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    def nearest_match(
        self, phash: Any, threshold: int | None = None
    ) -> tuple[str, int] | None:
        """Return ``(brand_domain, distance)`` for the closest allowed match."""
        selected = config.PHASH_DISTANCE_THRESHOLD if threshold is None else threshold
        selected = _validate_threshold(selected)
        query = parse_hash(phash)

        best: tuple[int, str] | None = None
        for brand_domain in sorted(self._entries):
            distance = hash_distance(query, self._entries[brand_domain])
            if distance <= selected:
                candidate = (distance, brand_domain)
                if best is None or candidate < best:
                    best = candidate
        return None if best is None else (best[1], best[0])


def demo() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "store.json")
        store = ReferenceStore(path)
        store.add("PayPal.COM.", "ffffffffffffffff")
        store.save()
        reloaded = ReferenceStore(path)
        assert reloaded.domains == ("paypal.com",)
        assert reloaded.nearest_match("fffffffffffffffe", threshold=1) == (
            "paypal.com",
            1,
        )
        assert reloaded.nearest_match("0000000000000000") is None
    print("reference_store: all checks passed")


if __name__ == "__main__":
    demo()
