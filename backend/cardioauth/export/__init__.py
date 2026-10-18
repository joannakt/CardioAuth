"""Export boundary (§8.6): letter AST → DOCX / PDF. Arrives in M6.

Export is the last gate before a letter leaves the system, so the interface is stated
here: an exporter receives an *immutable* letter version plus its verification run and
must refuse to write anything unless no sentence is ``unsupported``/``unverified``
(INV-3). It never contacts a payer.
"""

from __future__ import annotations

from typing import Any, Literal

Format = Literal["docx", "pdf"]


def export_letter_version(letter_version: Any, verification_run: Any, *, fmt: Format) -> bytes:  # pragma: no cover - M6
    raise NotImplementedError(
        "letter export (DOCX via python-docx, PDF via WeasyPrint) is implemented in M6, together "
        "with the claim-verification gate that refuses to export an unsupported sentence."
    )
