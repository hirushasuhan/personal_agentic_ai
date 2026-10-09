"""
Safe Ingestion Module for Phase 1 (ADR-011 / Days 2-3)
Enforces path boundaries, symlink safety, resource caps, binary detection,
secrets hygiene, and untrusted-data envelope wrapping.

Invariants:
1. Path resolution: os.path.realpath, rejects paths or symlinks escaping user root.
2. Device safety: rejects character/block devices, FIFOs, and sockets (fail-closed).
3. Secrets hygiene: denies sensitive files (.env, *.pem, id_rsa*, *.key) by name without reading.
4. Binary safety: detects NUL bytes (b'\\x00') and rejects binary files.
5. Text normalization: decodes UTF-8 (replace), normalizes newlines, strips non-printable control chars.
6. Resource limits: max file size, max total bytes, max file count, max depth.
7. Envelope wrapping: wraps data in UNTRUSTED DATA envelopes with internal marker defanging.
8. Zero execution: never executes, imports, or evals any ingested content.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import hashlib
import os
import re
import stat
from typing import Any, Dict, List, Optional, Set, Tuple

# -----------------------------------------------------------------------------
# Ingestion Limits & Defaults
# -----------------------------------------------------------------------------
DEFAULT_MAX_FILE_SIZE: int = 1_048_576      # 1 MB per file
DEFAULT_MAX_TOTAL_BYTES: int = 10_485_760   # 10 MB per run
DEFAULT_MAX_FILE_COUNT: int = 500           # 500 files per run
DEFAULT_MAX_DEPTH: int = 10                 # 10 subfolder levels
DEFAULT_MAX_LINE_LENGTH: int = 4096         # 4096 chars per line

DEFAULT_SECRET_DENY_PATTERNS: Tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "*.key",
    "*.pfx",
    "*.pkcs12",
    "*.kdbx",
    "credentials.json",
    "service_account*.json",
)

UNTRUSTED_BEGIN_MARKER = "--- UNTRUSTED DATA BEGIN ---"
UNTRUSTED_END_MARKER = "--- UNTRUSTED DATA END ---"


def get_ingest_limits() -> Dict[str, Any]:
    """Returns canonical ingestion limits dict for inspectability and CLI --json output."""
    return {
        "max_file_size_bytes": DEFAULT_MAX_FILE_SIZE,
        "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
        "max_file_count": DEFAULT_MAX_FILE_COUNT,
        "max_depth": DEFAULT_MAX_DEPTH,
        "max_line_length": DEFAULT_MAX_LINE_LENGTH,
        "secret_deny_patterns": list(DEFAULT_SECRET_DENY_PATTERNS),
    }


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class IngestedItem:
    path: str
    kind: str
    text: str
    truncated: bool
    sha256: str
    bytes_read: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "text": self.text,
            "truncated": self.truncated,
            "sha256": self.sha256,
            "bytes_read": self.bytes_read,
        }


@dataclasses.dataclass(frozen=True)
class IngestionRejection:
    path: str
    reason_code: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "reason_code": self.reason_code,
            "message": self.message,
        }


@dataclasses.dataclass
class IngestionReport:
    root: str
    items: List[IngestedItem]
    rejections: List[IngestionRejection]
    total_bytes: int
    total_files: int
    limits: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "items": [it.to_dict() for it in self.items],
            "rejections": [rej.to_dict() for rej in self.rejections],
            "total_bytes": self.total_bytes,
            "total_files": self.total_files,
            "limits": self.limits,
        }


# -----------------------------------------------------------------------------
# Sanitation & Normalization Helpers
# -----------------------------------------------------------------------------
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text_content(raw_bytes: bytes, max_line_length: int = DEFAULT_MAX_LINE_LENGTH) -> str:
    """
    Decodes raw bytes with explicit UTF-8 replacement policy, normalizes newlines,
    strips control characters (except newline and tab), and enforces line length caps.
    """
    text = raw_bytes.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_CHAR_RE.sub("", text)

    lines = text.split("\n")
    capped_lines = []
    for line in lines:
        if len(line) > max_line_length:
            capped_lines.append(line[:max_line_length] + " [TRUNCATED_LINE]")
        else:
            capped_lines.append(line)
    return "\n".join(capped_lines)


def is_secret_file(filename: str, deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS) -> bool:
    """Returns True if filename matches any pattern in secret deny list."""
    base = os.path.basename(filename).lower()
    for pat in deny_patterns:
        if fnmatch.fnmatch(base, pat.lower()):
            return True
    return False


def defang_envelope_markers(text: str) -> str:
    """Replaces embedded envelope markers to prevent prompt-injection delimiter hijacking."""
    sanitized = text.replace(UNTRUSTED_BEGIN_MARKER, "[STRIPPED_MARKER]")
    sanitized = sanitized.replace(UNTRUSTED_END_MARKER, "[STRIPPED_MARKER]")
    return sanitized


def wrap_untrusted_envelope(content: str, header: Optional[str] = None) -> str:
    """
    Wraps content inside standardized UNTRUSTED DATA envelope with internal marker defanging.
    """
    clean_body = defang_envelope_markers(content)
    lines = [UNTRUSTED_BEGIN_MARKER]
    if header:
        lines.append(f"Source: {header}")
    lines.append(clean_body)
    lines.append(UNTRUSTED_END_MARKER)
    return "\n".join(lines)


def format_untrusted_context(
    report: IngestionReport,
    char_budget: int = 32_000,
) -> str:
    """
    Assembles ingested items into an untrusted-data envelope block respecting a character budget.
    """
    sections = []
    current_chars = 0

    for item in report.items:
        item_header = f"File: {item.path} (SHA-256: {item.sha256[:16]}...)"
        wrapped = wrap_untrusted_envelope(item.text, header=item_header)

        if current_chars + len(wrapped) > char_budget:
            remaining = char_budget - current_chars
            if remaining > 200:
                truncated_text = item.text[: max(0, remaining - 150)] + "\n... [CONTEXT_BUDGET_TRUNCATED]"
                wrapped = wrap_untrusted_envelope(truncated_text, header=item_header)
                sections.append(wrapped)
            break

        sections.append(wrapped)
        current_chars += len(wrapped)

    return "\n\n".join(sections)


# -----------------------------------------------------------------------------
# Core Ingestion Logic
# -----------------------------------------------------------------------------
def ingest_file(
    file_path: str,
    root_path: Optional[str] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
) -> Tuple[Optional[IngestedItem], Optional[IngestionRejection]]:
    """
    Safely ingests a single file, verifying boundaries, secrets hygiene, and content validity.
    """
    if root_path is None:
        root_path = os.path.dirname(os.path.abspath(file_path))

    canonical_root = os.path.realpath(os.path.abspath(root_path))
    abs_target = os.path.abspath(file_path)

    # 1. Existence check
    if not os.path.lexists(abs_target):
        return None, IngestionRejection(
            path=file_path,
            reason_code="NOT_FOUND",
            message=f"Target file does not exist: {file_path}",
        )

    # 2. Symlink escape check
    if os.path.islink(abs_target):
        target_dest = os.path.realpath(abs_target)
        try:
            common = os.path.commonpath([canonical_root, target_dest])
        except ValueError:
            common = ""
        if common != canonical_root:
            return None, IngestionRejection(
                path=file_path,
                reason_code="SYMLINK_ESCAPE",
                message=f"Symlink points outside root boundary: {target_dest}",
            )

    # 3. Path boundary check
    real_target = os.path.realpath(abs_target)
    try:
        common = os.path.commonpath([canonical_root, real_target])
    except ValueError:
        common = ""
    if common != canonical_root:
        return None, IngestionRejection(
            path=file_path,
            reason_code="OUTSIDE_ROOT",
            message=f"Target path resolves outside root boundary: {real_target}",
        )

    # 4. Device / Special file check
    try:
        lst = os.lstat(abs_target)
        if not stat.S_ISREG(lst.st_mode) and not stat.S_ISLNK(lst.st_mode):
            return None, IngestionRejection(
                path=file_path,
                reason_code="SPECIAL_FILE",
                message=f"Target is a special device file or FIFO (mode {oct(lst.st_mode)})",
            )
        st = os.stat(real_target)
        if not stat.S_ISREG(st.st_mode):
            return None, IngestionRejection(
                path=file_path,
                reason_code="SPECIAL_FILE",
                message=f"Target resolves to a non-regular file (mode {oct(st.st_mode)})",
            )
    except Exception as e:
        return None, IngestionRejection(
            path=file_path,
            reason_code="STAT_ERROR",
            message=f"Failed to inspect file status: {e}",
        )

    # 5. Secrets hygiene check
    if is_secret_file(file_path, deny_patterns) or is_secret_file(real_target, deny_patterns):
        return None, IngestionRejection(
            path=file_path,
            reason_code="SECRET_FILE",
            message=f"Access denied to secret file pattern: {os.path.basename(file_path)}",
        )

    # 6. Read content with size capping
    try:
        with open(real_target, "rb") as f:
            raw_data = f.read(max_file_size + 1)
    except Exception as e:
        return None, IngestionRejection(
            path=file_path,
            reason_code="READ_ERROR",
            message=f"Failed to read file: {e}",
        )

    truncated = False
    if len(raw_data) > max_file_size:
        truncated = True
        raw_data = raw_data[:max_file_size]

    # 7. Binary check (NUL byte presence)
    if b"\x00" in raw_data:
        return None, IngestionRejection(
            path=file_path,
            reason_code="BINARY_CONTENT",
            message="Binary content detected (contains NUL bytes)",
        )

    # 8. Sanitize and normalize text
    norm_text = sanitize_text_content(raw_data, max_line_length=max_line_length)
    sha256_hash = hashlib.sha256(raw_data).hexdigest()

    # Relative display path
    try:
        rel_path = os.path.relpath(abs_target, canonical_root)
    except ValueError:
        rel_path = file_path

    item = IngestedItem(
        path=rel_path,
        kind="file",
        text=norm_text,
        truncated=truncated,
        sha256=sha256_hash,
        bytes_read=len(raw_data),
    )
    return item, None


def ingest_folder(
    folder_path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    deny_patterns: Tuple[str, ...] = DEFAULT_SECRET_DENY_PATTERNS,
) -> IngestionReport:
    """
    Recursively scans and safely ingests all text files within a folder boundary.
    Enforces total file count, total byte budget, max depth, symlink escapes, and secrets denial.
    """
    canonical_root = os.path.realpath(os.path.abspath(folder_path))
    limits = {
        "max_file_size_bytes": max_file_size,
        "max_total_bytes": max_total_bytes,
        "max_file_count": max_file_count,
        "max_depth": max_depth,
        "max_line_length": max_line_length,
        "secret_deny_patterns": list(deny_patterns),
    }

    if not os.path.exists(canonical_root) or not os.path.isdir(canonical_root):
        rejections = [
            IngestionRejection(
                path=folder_path,
                reason_code="NOT_FOUND",
                message=f"Root directory does not exist or is not a directory: {folder_path}",
            )
        ]
        return IngestionReport(
            root=folder_path,
            items=[],
            rejections=rejections,
            total_bytes=0,
            total_files=0,
            limits=limits,
        )

    items: List[IngestedItem] = []
    rejections: List[IngestionRejection] = []
    total_bytes = 0

    for current_dir, dirnames, filenames in os.walk(canonical_root, followlinks=False):
        # Calculate current recursion depth
        rel_dir = os.path.relpath(current_dir, canonical_root)
        depth = 0 if rel_dir == "." else len(rel_dir.split(os.sep))

        if depth > max_depth:
            rejections.append(
                IngestionRejection(
                    path=rel_dir,
                    reason_code="MAX_DEPTH_EXCEEDED",
                    message=f"Recursion depth {depth} exceeds max depth limit {max_depth}",
                )
            )
            dirnames.clear()  # Do not descend further into subdirectories
            continue

        # Sort for deterministic processing order
        filenames.sort()
        dirnames.sort()

        for fname in filenames:
            fpath = os.path.join(current_dir, fname)

            # Check file count limit
            if len(items) >= max_file_count:
                rejections.append(
                    IngestionRejection(
                        path=os.path.relpath(fpath, canonical_root),
                        reason_code="FILE_COUNT_EXCEEDED",
                        message=f"Max file count limit reached ({max_file_count})",
                    )
                )
                continue

            # Check total byte budget limit
            if total_bytes >= max_total_bytes:
                rejections.append(
                    IngestionRejection(
                        path=os.path.relpath(fpath, canonical_root),
                        reason_code="TOTAL_BYTES_EXCEEDED",
                        message=f"Total ingested byte budget reached ({max_total_bytes} bytes)",
                    )
                )
                continue

            item, rej = ingest_file(
                file_path=fpath,
                root_path=canonical_root,
                max_file_size=max_file_size,
                max_line_length=max_line_length,
                deny_patterns=deny_patterns,
            )

            if rej is not None:
                rejections.append(rej)
            elif item is not None:
                # Check if adding this item would exceed total bytes
                if total_bytes + item.bytes_read > max_total_bytes:
                    rejections.append(
                        IngestionRejection(
                            path=item.path,
                            reason_code="TOTAL_BYTES_EXCEEDED",
                            message=f"Ingesting {item.bytes_read} bytes would exceed total budget ({max_total_bytes})",
                        )
                    )
                else:
                    items.append(item)
                    total_bytes += item.bytes_read

    return IngestionReport(
        root=canonical_root,
        items=items,
        rejections=rejections,
        total_bytes=total_bytes,
        total_files=len(items),
        limits=limits,
    )
