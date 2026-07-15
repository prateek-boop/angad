"""Converts URL characters into integer IDs for the CNN branch. See
MODEL_BRAIN.md sec 4A: max length 200, pad=0, unknown=1, printable ASCII charset."""

import numpy as np

from config import MODEL_CONFIG

MAX_URL_LENGTH = MODEL_CONFIG["max_url_length"]
VOCAB_SIZE = MODEL_CONFIG["vocab_size"]

PAD_ID = 0
UNKNOWN_ID = 1
# Printable ASCII 32..126 (space..~) mapped to ids 2..96, leaving room under
# vocab_size=128 without needing a hand-built lookup table.
_PRINTABLE_LOW, _PRINTABLE_HIGH = 32, 126


def _char_to_id(ch: str) -> int:
    code = ord(ch)
    if _PRINTABLE_LOW <= code <= _PRINTABLE_HIGH:
        idx = code - _PRINTABLE_LOW + 2
        if idx < VOCAB_SIZE:
            return idx
    return UNKNOWN_ID


class URLTokenizer:
    """Stateless char tokenizer — no fitting/vocab-building step needed since
    the charset is fixed printable ASCII."""

    def __init__(self, max_length: int = MAX_URL_LENGTH):
        self.max_length = max_length

    def encode(self, url: str) -> list[int]:
        ids = [_char_to_id(c) for c in url[: self.max_length]]
        ids += [PAD_ID] * (self.max_length - len(ids))
        return ids

    def encode_batch(self, urls: list[str]) -> np.ndarray:
        return np.array([self.encode(u) for u in urls], dtype=np.int32)


def demo():
    tok = URLTokenizer()
    ids = tok.encode("http://example.com/login")
    assert len(ids) == MAX_URL_LENGTH
    assert ids[0] != PAD_ID
    assert all(i == PAD_ID for i in ids[len("http://example.com/login") :])

    long_url = "http://example.com/" + "a" * 300
    ids_long = tok.encode(long_url)
    assert len(ids_long) == MAX_URL_LENGTH  # truncated, not overflowed

    ids_unicode = tok.encode("http://пример.рф/")
    assert UNKNOWN_ID in ids_unicode  # non-ASCII chars map to unknown

    batch = tok.encode_batch(["http://a.com", "http://b.com"])
    assert batch.shape == (2, MAX_URL_LENGTH)
    print("url_tokenizer: all checks passed")


if __name__ == "__main__":
    demo()
