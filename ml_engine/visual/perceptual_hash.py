"""Deterministic perceptual hashing for Tier 4 screenshot comparison.

Pillow and ImageHash are optional runtime dependencies. Importing this module
does not make Tier 0-3 unusable when they are absent; callers get a focused
``PerceptualHashUnavailable`` error only when visual hashing is requested.
"""

from __future__ import annotations

import io
from typing import Any

import config

try:  # Keep the rest of ShieldNet importable without Tier 4 dependencies.
    import imagehash
    from PIL import Image, ImageOps, UnidentifiedImageError
except ImportError as exc:  # pragma: no cover - exercised through a subprocess test
    imagehash = None
    Image = None
    ImageOps = None
    UnidentifiedImageError = OSError
    _DECOMPRESSION_BOMB_ERROR = OSError
    _IMPORT_ERROR: ImportError | None = exc
else:
    _DECOMPRESSION_BOMB_ERROR = Image.DecompressionBombError
    _IMPORT_ERROR = None


PHASH_SIZE = 8
PHASH_HEX_LENGTH = PHASH_SIZE * PHASH_SIZE // 4
MAX_IMAGE_PIXELS = 25_000_000
_SUPPORTED_FORMATS = {"JPEG", "PNG"}


class PerceptualHashUnavailable(RuntimeError):
    """Raised when Pillow/ImageHash are not installed."""


class InvalidImageError(ValueError):
    """Raised when input cannot be safely decoded as a supported image."""


def _require_backend() -> None:
    if _IMPORT_ERROR is not None:
        raise PerceptualHashUnavailable(
            "Tier 4 hashing requires Pillow and ImageHash; install the visual "
            "dependencies to enable screenshot comparison"
        ) from _IMPORT_ERROR


def _coerce_hash(value: Any):
    """Return a standard 64-bit ImageHash from an ImageHash or hex string."""
    _require_backend()
    if isinstance(value, str):
        raw = value.strip().lower()
        if len(raw) != PHASH_HEX_LENGTH or any(
            c not in "0123456789abcdef" for c in raw
        ):
            raise ValueError(
                f"perceptual hash must be {PHASH_HEX_LENGTH} hexadecimal characters"
            )
        try:
            value = imagehash.hex_to_hash(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid perceptual hash") from exc

    if not isinstance(value, imagehash.ImageHash):
        raise TypeError("perceptual hash must be an ImageHash or hexadecimal string")
    if tuple(value.hash.shape) != (PHASH_SIZE, PHASH_SIZE):
        raise ValueError(f"perceptual hash must contain {PHASH_SIZE * PHASH_SIZE} bits")
    return value


def parse_hash(value: Any):
    """Parse and validate the project's canonical 64-bit pHash representation."""
    return _coerce_hash(value)


def serialize_hash(value: Any) -> str:
    """Return a lowercase, fixed-width hexadecimal pHash string."""
    return str(_coerce_hash(value)).lower()


def _validate_threshold(threshold: int) -> int:
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise TypeError("visual match threshold must be an integer")
    if not 0 <= threshold <= PHASH_SIZE * PHASH_SIZE:
        raise ValueError("visual match threshold must be between 0 and 64")
    return threshold


def hash_image_bytes(image_bytes: bytes | bytearray | memoryview):
    """Return a canonical 64-bit pHash for PNG or JPEG image bytes.

    Images are orientation-normalized and composited onto white before hashing,
    which makes alpha handling deterministic across callers. A pixel limit is
    enforced before decoding to avoid oversized-image memory exhaustion.
    """
    _require_backend()
    if not isinstance(image_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("image_bytes must be bytes-like")
    raw = bytes(image_bytes)
    if not raw:
        raise InvalidImageError("image is empty")

    try:
        with Image.open(io.BytesIO(raw)) as source:
            if source.format not in _SUPPORTED_FORMATS:
                raise InvalidImageError("only PNG and JPEG screenshots are supported")
            width, height = source.size
            pixels = width * height
            if width <= 0 or height <= 0 or pixels > MAX_IMAGE_PIXELS:
                raise InvalidImageError(
                    f"image dimensions exceed the {MAX_IMAGE_PIXELS:,}-pixel safety limit"
                )
            source.load()
            oriented = ImageOps.exif_transpose(source)
            rgba = oriented.convert("RGBA")
            background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            normalized = Image.alpha_composite(background, rgba).convert("RGB")
            return imagehash.phash(normalized, hash_size=PHASH_SIZE)
    except InvalidImageError:
        raise
    except (
        UnidentifiedImageError,
        _DECOMPRESSION_BOMB_ERROR,
        OSError,
        SyntaxError,
        ValueError,
    ) as exc:
        raise InvalidImageError("image could not be decoded") from exc


def hash_distance(hash_a: Any, hash_b: Any) -> int:
    """Return the Hamming distance between two canonical pHashes."""
    return int(_coerce_hash(hash_a) - _coerce_hash(hash_b))


def is_visual_match(hash_a: Any, hash_b: Any, threshold: int | None = None) -> bool:
    """Return whether two hashes are within the configured Hamming distance."""
    selected = config.PHASH_DISTANCE_THRESHOLD if threshold is None else threshold
    return hash_distance(hash_a, hash_b) <= _validate_threshold(selected)


def demo() -> None:
    _require_backend()
    buffer = io.BytesIO()
    image = Image.new("RGB", (64, 64), "white")
    for x in range(8, 28):
        for y in range(12, 52):
            image.putpixel((x, y), (0, 0, 0))
    image.save(buffer, format="PNG")

    first = hash_image_bytes(buffer.getvalue())
    second = hash_image_bytes(buffer.getvalue())
    assert serialize_hash(first) == serialize_hash(second)
    assert hash_distance(first, second) == 0
    assert is_visual_match(first, second, threshold=0)
    print("perceptual_hash: all checks passed")


if __name__ == "__main__":
    demo()
