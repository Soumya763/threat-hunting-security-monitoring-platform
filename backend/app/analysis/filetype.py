"""
File-type identification from magic bytes, plus extension policy.

The declared extension is never trusted on its own. The leading bytes of
the file are matched against known signatures, and the detected family is
compared with the extension. A mismatch (for example an `invoice.pdf` whose
bytes are a Windows PE executable) is reported as an indicator, not
silently accepted.

This is a deliberately small signature table covering the MVP formats
(EXE/DLL, PDF, DOC/DOCX, ZIP, PNG, JPG/JPEG). python-magic (libmagic) is not
used so the module has no native dependency; the table can be extended
later.
"""

from typing import Any

# Extension -> set of detected families that legitimately carry it.
ALLOWED_EXTENSIONS: dict[str, frozenset[str]] = {
    "exe": frozenset({"pe_executable"}),
    "dll": frozenset({"pe_executable"}),
    "pdf": frozenset({"pdf"}),
    "doc": frozenset({"ole_compound"}),
    "docx": frozenset({"zip_container"}),
    "zip": frozenset({"zip_container"}),
    "png": frozenset({"png"}),
    "jpg": frozenset({"jpeg"}),
    "jpeg": frozenset({"jpeg"}),
}

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def detect_family(head: bytes) -> str | None:
    """Return the detected file family from the leading bytes, or None."""
    if head.startswith(b"MZ") and len(head) >= 0x40:
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        if e_lfanew + 4 <= len(head) and head[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return "pe_executable"
        return "dos_mz"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(_PNG_MAGIC):
        return "png"
    if head.startswith(_JPEG_MAGIC):
        return "jpeg"
    if head.startswith(_OLE_MAGIC):
        return "ole_compound"
    if head.startswith(_ZIP_MAGICS):
        return "zip_container"
    return None


def declared_extension(filename: str | None) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


def identify(filename: str | None, head: bytes) -> dict[str, Any]:
    """
    Compare the declared extension with the magic-byte family.

    Returns:
      declared_extension  - lower-cased extension from the filename ("" if none)
      extension_allowed   - True if the extension is on the MVP allow-list
      detected_family     - family from magic bytes, or None if unrecognised
      extension_matches   - True/False when both sides are known, else None
      warnings            - human-readable reasons, safe to show in a report
    """
    ext = declared_extension(filename)
    family = detect_family(head)
    allowed = ext in ALLOWED_EXTENSIONS

    matches: bool | None = None
    warnings: list[str] = []

    if not allowed:
        warnings.append(
            f"Extension '.{ext}' is not on the supported list." if ext
            else "The file has no extension."
        )

    if family is None:
        warnings.append("The file's leading bytes do not match any supported format.")
    elif allowed:
        matches = family in ALLOWED_EXTENSIONS[ext]
        if not matches:
            warnings.append(
                f"Extension '.{ext}' does not match the detected content type "
                f"'{family}' (possible disguised file)."
            )

    return {
        "declared_extension": ext,
        "extension_allowed": allowed,
        "detected_family": family,
        "extension_matches": matches,
        "warnings": warnings,
    }
