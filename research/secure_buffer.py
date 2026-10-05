"""
SecureBuffer - wipeable working memory for the Stateless Purge Protocol.

Python `str` and `bytes` are immutable: `del text` only drops a reference, it never
overwrites the bytes. A bytearray, however, can be overwritten in place. Every piece
of ingested data therefore lives in a SecureBuffer, and wipe() really zeroes it and
VERIFIES the result.

Honest limitation (documented in docs/THREAT_MODEL.md): any `str` copy created via
.text() is outside our control (CPython frees it without zeroing). The prototype
minimises such copies; the Rust core (Phase 3, `zeroize` crate) removes the problem.
"""

from __future__ import annotations

import ctypes
from typing import Optional, Union


class BufferOverflow(Exception):
    pass


class SecureBuffer:
    def __init__(self, data: Union[bytes, str, None] = None, label: str = "buffer", capacity: Optional[int] = None):
        self.label = label
        self.capacity = capacity
        self._buf = bytearray()
        self._wiped = False
        self.bytes_wiped = 0
        if data is not None:
            self.write(data)

    def write(self, data: Union[bytes, str]) -> None:
        if self._wiped:
            raise ValueError("SecureBuffer already wiped")
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if self.capacity is not None and len(self._buf) + len(raw) > self.capacity:
            raise BufferOverflow(f"{self.label}: {len(self._buf) + len(raw)} B exceeds capacity {self.capacity} B")
        self._buf.extend(raw)

    def __len__(self) -> int:
        return len(self._buf)

    @property
    def wiped(self) -> bool:
        return self._wiped

    def view(self) -> memoryview:
        """Zero-copy read access. Release the view before calling wipe()."""
        return memoryview(self._buf)

    def text(self, errors: str = "replace") -> str:
        """Creates a str COPY (cannot be zeroed). Use sparingly."""
        return self._buf.decode("utf-8", errors=errors)

    def wipe(self) -> bool:
        """Overwrites the buffer with zeros, verifies it, then releases it. Idempotent."""
        if self._wiped:
            return True
        n = len(self._buf)
        verified = True
        if n:
            arr = (ctypes.c_char * n).from_buffer(self._buf)
            ctypes.memset(arr, 0, n)
            del arr  # release the buffer export so the bytearray can be resized
            verified = self._buf.count(0) == n
        self.bytes_wiped = n
        try:
            self._buf.clear()
        except BufferError:  # an external view() is still alive; bytes are already zero
            pass
        self._wiped = True
        return verified

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, *exc) -> None:
        self.wipe()

    def __repr__(self) -> str:  # never print contents
        return f"<SecureBuffer {self.label!r} len={len(self._buf)} wiped={self._wiped}>"
