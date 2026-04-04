import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from db.client import get_db  # noqa: E402
from db.operations import FRAUD_PATTERNS, upsert_fraud_pattern_record  # noqa: E402


def backfill_embeddings() -> None:
    db = get_db()
    if not db:
        print("[FAIL] Firestore client unavailable")
        raise SystemExit(1)

    total = 0
    updated = 0
    skipped = 0
    failed = 0

    for doc in db.collection(FRAUD_PATTERNS).stream():
        total += 1
        payload = doc.to_dict() or {}
        if payload.get("embedding") and payload.get("embedding_model"):
            skipped += 1
            continue

        payload["id"] = doc.id
        ok = upsert_fraud_pattern_record(payload)
        if ok:
            updated += 1
            print(f"[OK] embedded: {doc.id}")
        else:
            failed += 1
            print(f"[FAIL] {doc.id}")

    print("-")
    print(f"total={total} updated={updated} skipped={skipped} failed={failed}")


if __name__ == "__main__":
    backfill_embeddings()
