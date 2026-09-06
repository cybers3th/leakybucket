"""Multimodal ingest — extract text from images / audio / PDFs so text
detectors can inspect it.

Each extractor is optional; if the corresponding backend isn't installed,
the extractor raises RuntimeError, and callers fall back to a "raw hash"
mode that at least marks the artifact as unknown-untrusted.
"""
from firewall.multimodal.extract import (
    extract_text, extract_image_text, extract_pdf_text, extract_audio_text,
    ExtractionResult, hash_artifact,
)

__all__ = [
    "extract_text", "extract_image_text", "extract_pdf_text",
    "extract_audio_text", "ExtractionResult", "hash_artifact",
]
