"""OCR boundary (§5.1). Implementations arrive in M2 (text layer, Tesseract, Textract).

The interface is fixed now because ``page_text_version.text_normalized`` and every
``fact_span`` offset depend on the normalisation rules (§2.4) that the backend must
report: an OCR backend returns page text plus its method and confidence, and the
*service* normalises it, so the offsets in stored spans are reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cardioauth.settings import Settings, get_settings


@dataclass(frozen=True)
class OcrPage:
    page_number: int
    text: str
    method: str  # 'text_layer' | 'tesseract' | 'textract' | 'pasted'
    confidence: float | None
    width_px: int | None = None
    height_px: int | None = None
    render_dpi: int | None = None
    image_bytes: bytes | None = None


@runtime_checkable
class OcrBackend(Protocol):
    def extract(self, data: bytes, *, mime_type: str) -> list[OcrPage]: ...


def get_ocr_backend(settings: Settings | None = None) -> OcrBackend:  # pragma: no cover - M2
    settings = settings or get_settings()
    raise NotImplementedError(
        f"OCR backend '{settings.ocr_backend}' is implemented in M2 "
        "(pdf_text_layer, tesseract, textract). Nothing is wired yet, by design."
    )
