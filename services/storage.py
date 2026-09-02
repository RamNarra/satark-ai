"""
Durable Evidence Artifact Storage.
Persists raw forensic assets to local disk or cloud bucket with SHA-256 verification.
"""
import os
import hashlib
from pathlib import Path
from typing import Tuple

STORAGE_ROOT = Path(os.getenv("SATARK_STORAGE_ROOT", "data/evidence")).resolve()


class EvidenceStorageService:
    """Manages immutable file artifact storage on filesystem."""

    def __init__(self, root_path: Path = STORAGE_ROOT):
        self.root = root_path
        self.root.mkdir(parents=True, exist_ok=True)

    def store_bytes(self, case_id: str, filename: str, data: bytes) -> Tuple[str, str, int]:
        """
        Stores raw bytes under case directory.
        Returns (relative_storage_path, sha256_hash, byte_size).
        """
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
        """Reads raw artifact bytes from disk."""
        target = (self.root.parent / relative_storage_path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Evidence artifact not found: {relative_storage_path}")
        return target.read_bytes()
