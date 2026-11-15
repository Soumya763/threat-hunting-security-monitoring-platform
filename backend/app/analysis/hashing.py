"""
Streaming file hashing with a hard size cap.

Computes MD5, SHA-1 and SHA-256 in one pass over the file, reading in
fixed-size chunks so memory use is bounded regardless of file size. The
size cap is enforced while reading, so an oversized upload is rejected
before it is fully consumed.

MD5 and SHA-1 are computed only because threat-intelligence providers
index samples by them. They are not used for any security decision in
this code base.
"""

import hashlib
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024


class FileTooLargeError(ValueError):
    """Raised when a stream exceeds the configured maximum size."""


def hash_stream(fp: BinaryIO, max_bytes: int) -> dict:
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    size = 0

    while True:
        chunk = fp.read(CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        if size > max_bytes:
            raise FileTooLargeError(f"File exceeds the {max_bytes}-byte limit.")
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)

    return {
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def hash_bytes(data: bytes, max_bytes: int) -> dict:
    import io

    return hash_stream(io.BytesIO(data), max_bytes)
