"""Text transformations used to obfuscate payloads (library directives and mutator)."""
from __future__ import annotations

import base64
import codecs
import re

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7"})
# Latin letters replaced by visually identical Cyrillic/Greek code points.
_HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і",
               "A": "А", "E": "Е", "O": "О", "P": "Р", "C": "С", "T": "Т", "H": "Н", "B": "В", "M": "М"}
ZERO_WIDTH = "\u200b"  # zero-width space


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def hexenc(text: str) -> str:
    return text.encode().hex()


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def leet(text: str) -> str:
    return text.translate(_LEET)


def homoglyph(text: str) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def zero_width(text: str) -> str:
    """Insert a zero-width space inside every word of 4+ letters, breaking keyword matching."""
    return re.sub(r"[A-Za-z]{4,}", lambda m: ZERO_WIDTH.join(m.group(0)), text)


def reverse(text: str) -> str:
    return text[::-1]


def spaced(text: str) -> str:
    return " ".join(text)


DIRECTIVES = {"b64": b64, "hex": hexenc, "rot13": rot13, "leet": leet, "homoglyph": homoglyph,
              "zw": zero_width, "reverse": reverse, "spaced": spaced}
_DIRECTIVE_RE = re.compile(r"\{\{(\w+):(.*?)\}\}", re.DOTALL)


def expand_directives(text: str) -> str:
    """Replace ``{{name:content}}`` with transform ``name`` applied to ``content``.

    This lets payload YAML stay human-readable while the stored/sent text is truly obfuscated.
    """
    def repl(m: re.Match[str]) -> str:
        fn = DIRECTIVES.get(m.group(1))
        if fn is None:
            raise ValueError(f"unknown payload directive '{m.group(1)}'")
        return fn(m.group(2))

    return _DIRECTIVE_RE.sub(repl, text)
