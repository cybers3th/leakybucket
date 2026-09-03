"""Input normalization for detectors.

Attackers hide instructions with encoding, invisible characters, homoglyphs,
zero-width joiners, weird spacing, etc. Detectors should look at *both*
raw text and a normalized view — otherwise the classifier will silently miss
attacks that a human would obviously recognise.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse

# Common invisible / bidi / formatting characters used to hide injections
INVISIBLE_CHARS = "".join([
    "​", "‌", "‍", "⁠", "﻿",     # zero-width family
    "‪", "‫", "‬", "‭", "‮",     # bidi controls
    "⁦", "⁧", "⁨", "⁩",               # isolates
    "᠎", "͏",
])

HOMOGLYPH_TABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",  # cyrillic
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y", "Х": "X",
    "і": "i", "І": "I", "ј": "j", "Ј": "J",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t",                                  # greek
    "⁄": "/", "∕": "/",
    "–": "-", "—": "-",
    "“": '"', "”": '"', "‘": "'", "’": "'",
})


def strip_invisibles(text: str) -> str:
    return "".join(ch for ch in text if ch not in INVISIBLE_CHARS)


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def normalize_basic(text: str) -> str:
    """Deterministic normalization used by pattern detectors."""
    if not text:
        return ""
    t = strip_invisibles(text)
    t = nfkc(t)
    t = t.translate(HOMOGLYPH_TABLE)
    t = html.unescape(t)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    return t


# Encoding decoders — return a list of decoded views to also scan
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/=]{24,}={0,2})")
_HEX_RE    = re.compile(r"(?:[0-9a-fA-F]{2}\s*){12,}")
_URL_RE    = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_ROT13_HINT_RE = re.compile(r"[a-zA-Z ]{80,}")


def decoded_views(text: str, max_views: int = 6) -> list[str]:
    """Return additional decoded views to also scan for suspicious content."""
    views: list[str] = []

    for m in _BASE64_RE.findall(text)[:max_views]:
        try:
            data = base64.b64decode(m, validate=False)
            if not data:
                continue
            s = data.decode("utf-8", errors="ignore")
            if _has_printable(s):
                views.append(s)
        except (binascii.Error, ValueError):
            pass

    for m in _HEX_RE.findall(text)[:max_views]:
        try:
            data = bytes.fromhex(re.sub(r"\s+", "", m))
            s = data.decode("utf-8", errors="ignore")
            if _has_printable(s):
                views.append(s)
        except ValueError:
            pass

    for m in _URL_RE.findall(text)[:max_views]:
        try:
            s = urllib.parse.unquote(m)
            if s != m and _has_printable(s):
                views.append(s)
        except Exception:
            pass

    if _ROT13_HINT_RE.search(text):
        try:
            rot = codecs.decode(text, "rot_13")
            if rot != text:
                views.append(rot[:4000])
        except Exception:
            pass

    return views


def _has_printable(s: str, min_chars: int = 8) -> bool:
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable >= min_chars


def all_views(text: str) -> list[str]:
    """Views used by every detector: raw, normalized, and decoded."""
    base = normalize_basic(text)
    views = [text, base]
    if base != text:
        pass
    for v in decoded_views(text):
        views.append(normalize_basic(v))
    return views
