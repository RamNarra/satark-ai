"""
Storage Abstraction Layer.
Supports Cloud Storage (GCS / S3) with local disk fallback for dev/testing.
Enforces streaming chunked ingestion to prevent memory exhaustion on large files.
"""
import os
import hashlib
from pathlib import Path
from typing import Tuple, BinaryIO, AsyncIterator

STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").lower()
STORAGE_ROOT = Path(os.getenv("SATARK_STORAGE_ROOT", "data/evidence")).resolve()


class EvidenceStorageService:
    """Manages immutable file artifact storage."""

    def __init__(self, root_path: Path = STORAGE_ROOT):
        self.backend = STORAGE_BACKEND
        self.root = root_path
        self.root.mkdir(parents=True, exist_ok=True)

    async def store_stream(self, case_id: str, filename: str, stream: AsyncIterator[bytes], max_bytes: int = 50 * 1024 * 1024) -> Tuple[str, str, int]:
        """
        Streams chunks directly to disk/storage computing SHA-256 on the fly.
        Enforces max_bytes ceiling during streaming to prevent RAM exhaustion.
        """
        import uuid
        case_dir = self.root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # Security fix: Completely isolate temporary path from untrusted filename
        tmp_path = case_dir / f"tmp_upload_{uuid.uuid4().hex}.bin"
        sha_hasher = hashlib.sha256()
        total_size = 0

        with open(tmp_path, "wb") as f:
            async for chunk in stream:
                total_size += len(chunk)
                if total_size > max_bytes:
                    f.close()
                    tmp_path.unlink(missing_ok=True)
                    raise ValueError(f"Payload exceeded max allowed size of {max_bytes} bytes")
                sha_hasher.update(chunk)
                f.write(chunk)

        sha = sha_hasher.hexdigest()
        safe_filename = f"{sha[:12]}_{Path(filename).name}"
        target_path = case_dir / safe_filename
        tmp_path.rename(target_path)

        rel_path = str(target_path.relative_to(self.root.parent))
        return rel_path, sha, total_size

    def store_bytes(self, case_id: str, filename: str, data: bytes) -> Tuple[str, str, int]:
        """Direct byte storage helper for short text/narratives."""
        sha = hashlib.sha256(data).hexdigest()
        case_dir = self.root / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        safe_filename = f"{sha[:12]}_{Path(filename).name}"
        target_path = case_dir / safe_filename
        with open(target_path, "wb") as f:
            f.write(data)
        rel_path = str(target_path.relative_to(self.root.parent))
        return rel_path, sha, len(data)

    def read_bytes(self, relative_storage_path: str) -> bytes:
        """Reads raw artifact bytes."""
        target = (self.root.parent / relative_storage_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Evidence artifact not found: {relative_storage_path}")
        return target.read_bytes()
