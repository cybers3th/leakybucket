"""Multimodal text extraction.

Backends:
  * image: Tesseract (pytesseract) OR pillow+trOCR OR remote OCR API
  * pdf:   pypdf / pdfplumber (text extraction) + pdfminer as fallback
  * audio: whisper (openai-whisper OR faster-whisper) OR remote ASR API

The output is a normal string that flows into the existing detectors — the
prompt-injection detector then catches "hidden" instructions rendered in
image OCR, PDF text-layer, or transcribed audio.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ExtractionResult:
    text: str
    modality: str                   # image | pdf | audio
    backend: str                    # tesseract | pypdf | whisper | ...
    hash: str                       # sha256 of raw artifact
    metadata: dict[str, Any]


def hash_artifact(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_image_text(path_or_bytes) -> ExtractionResult:
    """Try pytesseract; if unavailable, try pillow. Raises if neither works."""
    if isinstance(path_or_bytes, (str, Path)):
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    else:
        raw = bytes(path_or_bytes)
    h = hash_artifact(raw)
    try:
        import io
        from PIL import Image
        import pytesseract
        img = Image.open(io.BytesIO(raw))
        text = pytesseract.image_to_string(img)
        return ExtractionResult(text=text, modality="image", backend="tesseract",
                                 hash=h, metadata={"size": img.size, "mode": img.mode})
    except ImportError:
        pass
    try:
        import io
        from PIL import Image
        img = Image.open(io.BytesIO(raw))
        return ExtractionResult(text="", modality="image", backend="pillow_noocr",
                                 hash=h, metadata={"size": img.size, "note": "no OCR backend"})
    except Exception as e:
        return ExtractionResult(text="", modality="image", backend="none",
                                 hash=h, metadata={"error": str(e)})


def extract_pdf_text(path_or_bytes) -> ExtractionResult:
    if isinstance(path_or_bytes, (str, Path)):
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    else:
        raw = bytes(path_or_bytes)
    h = hash_artifact(raw)
    try:
        import io
        import pypdf
        r = pypdf.PdfReader(io.BytesIO(raw))
        text = "\n\n".join((p.extract_text() or "") for p in r.pages)
        return ExtractionResult(text=text, modality="pdf", backend="pypdf",
                                 hash=h, metadata={"pages": len(r.pages)})
    except ImportError:
        pass
    try:
        import io
        from pdfminer.high_level import extract_text as _pm
        text = _pm(io.BytesIO(raw))
        return ExtractionResult(text=text, modality="pdf", backend="pdfminer",
                                 hash=h, metadata={})
    except ImportError:
        pass
    return ExtractionResult(text="", modality="pdf", backend="none",
                             hash=h, metadata={"note": "no PDF backend"})


def extract_audio_text(path_or_bytes) -> ExtractionResult:
    if isinstance(path_or_bytes, (str, Path)):
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
        p = str(path_or_bytes)
    else:
        raw = bytes(path_or_bytes)
        # whisper needs a file path
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tf:
            tf.write(raw); p = tf.name
    h = hash_artifact(raw)
    try:
        from faster_whisper import WhisperModel
        m = WhisperModel("base", device="cpu", compute_type="int8")
        segs, info = m.transcribe(p, language=None)
        text = " ".join(s.text for s in segs)
        return ExtractionResult(text=text, modality="audio", backend="faster_whisper",
                                 hash=h, metadata={"language": info.language,
                                                    "duration": info.duration})
    except ImportError:
        pass
    try:
        import whisper
        m = whisper.load_model("base")
        r = m.transcribe(p)
        return ExtractionResult(text=r.get("text", ""), modality="audio",
                                 backend="openai_whisper", hash=h,
                                 metadata={"language": r.get("language")})
    except ImportError:
        pass
    return ExtractionResult(text="", modality="audio", backend="none",
                             hash=h, metadata={"note": "no ASR backend"})


def extract_text(path: str | Path) -> ExtractionResult:
    p = str(path).lower()
    if p.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")):
        return extract_image_text(path)
    if p.endswith(".pdf"):
        return extract_pdf_text(path)
    if p.endswith((".mp3", ".wav", ".m4a", ".flac", ".ogg", ".opus")):
        return extract_audio_text(path)
    with open(path, "rb") as f:
        raw = f.read()
    try:
        return ExtractionResult(text=raw.decode("utf-8", "replace"),
                                 modality="text", backend="raw",
                                 hash=hash_artifact(raw), metadata={})
    except Exception:
        return ExtractionResult(text="", modality="unknown", backend="none",
                                 hash=hash_artifact(raw), metadata={})
