import argparse
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from google.cloud.firestore_v1.vector import Vector  # type: ignore

from db.client import get_db
from db.operations import CASES, FRAUD_PATTERNS


# Seed distribution (scaled to --count). Base values are intentionally a bit
# uneven so judges see realistic per-type volumes.
BASE_DISTRIBUTION = {
    "KYC Fraud": 312,
    "UPI Impersonation": 198,
    "OTP Phishing": 156,
    "Job Scam": 89,
    "Investment Fraud": 61,
    "Electricity Bill": 31,
    "Loan App Threat": 21,
    "Other": 10,
}

TRIGGER_PHRASES = {
    "UPI Impersonation": ["accept request", "scan qr", "collect request", "1 rupee verification"],
    "KYC Fraud": ["kyc update", "account blocked", "verify aadhaar", "update pan"],
    "OTP Phishing": ["share otp", "verification otp", "refund processing", "secure your account"],
    "Job Scam": ["work from home", "like and earn", "prepaid task", "daily income"],
    "Investment Fraud": ["guaranteed returns", "vip trading group", "withdrawal fee", "limited slots"],
    "Electricity Bill": ["tsecl", "electricity bill", "power disconnection", "pay now"],
    "Loan App Threat": ["instant loan", "no cibil", "approval in 5 minutes", "download app"],
    "Other": ["urgent verification", "limited time", "pay fee"],
}

MESSAGE_TEMPLATES = [
    "Urgent: {phrase}. Complete verification now to avoid penalty.",
    "Hello, we noticed suspicious activity. {phrase}. Please act immediately.",
    "Congratulations! {phrase}. Claim within 2 hours.",
    "Final reminder: {phrase}. Your account will be blocked today.",
    "We will help you recover funds. {phrase}. Stay on call.",
]


def _scale_distribution(target_total: int) -> list[tuple[str, int]]:
    items = [(k, int(v)) for k, v in BASE_DISTRIBUTION.items() if int(v) > 0]
    base_total = sum(v for _, v in items) or 1
    target = max(0, int(target_total))
    if target == 0:
        return []

    scaled = []
    remainders = []
    running = 0
    for k, v in items:
        exact = v * (target / base_total)
        n = int(math.floor(exact))
        scaled.append([k, n])
        remainders.append((k, exact - n))
        running += n

    remaining = target - running
    remainders.sort(key=lambda x: x[1], reverse=True)
    idx = 0
    while remaining > 0 and remainders:
        k, _r = remainders[idx % len(remainders)]
        for row in scaled:
            if row[0] == k:
                row[1] += 1
                break
        remaining -= 1
        idx += 1

    return [(k, int(n)) for k, n in scaled if int(n) > 0]


def _unit_random_vector(rng: random.Random, dim: int) -> list[float]:
    vec = [rng.uniform(-1.0, 1.0) for _ in range(dim)]
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def seed_firestore(
    count: int,
    seed: int,
    embed_dim: int,
    do_patterns: bool,
    do_cases: bool,
    dry_run: bool,
    *,
    batch_size: int,
    start_index: int,
) -> None:
    db = get_db()
    if not db:
        raise RuntimeError("Firestore client not available (check GOOGLE_APPLICATION_CREDENTIALS / ADC)")

    rng = random.Random(seed)
    now = datetime.now(timezone.utc)

    writes = 0
    ops_in_batch = 0
    batch = db.batch()

    def commit() -> None:
        nonlocal batch, ops_in_batch
        if dry_run:
            batch = db.batch()
            ops_in_batch = 0
            return
        batch.commit()
        batch = db.batch()
        ops_in_batch = 0

    def maybe_commit(force: bool = False) -> None:
        # Firestore batch commits are limited to 500 ops.
        # Keep a safety cap below that, and allow user-controlled smaller batches
        # to avoid DEADLINE_EXCEEDED on slow networks.
        hard_cap = 450
        effective = max(1, min(int(batch_size), hard_cap))
        if force or ops_in_batch >= effective or ops_in_batch >= hard_cap:
            commit()

    distribution = _scale_distribution(count)
    i = max(0, int(start_index))
    for scam_type, type_count in distribution:
        phrases = TRIGGER_PHRASES.get(scam_type, ["urgent verification"])
        severity = "CRITICAL" if scam_type in {"KYC Fraud", "Investment Fraud"} else "HIGH"
        for _ in range(int(type_count)):
            phrase = rng.choice(phrases)
            msg = rng.choice(MESSAGE_TEMPLATES).format(phrase=phrase)

            # Spread timestamps across the past 365 days.
            dt = now - timedelta(days=rng.randint(1, 365), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))

            if do_patterns:
                doc_id = f"demo_pat_{i:04d}"
                embedding = _unit_random_vector(rng, embed_dim)
                payload = {
                    "id": doc_id,
                    "scam_type": scam_type,
                    "sub_type": scam_type,
                    "official_category": scam_type,
                    "severity": severity,
                    "active": True,
                    "year": dt.year,
                    "timestamp": _iso(dt),
                    "updated_at": _iso(now),
                    "preview": msg[:200],
                    "trigger_phrases": phrases,
                    "example_messages": [msg, (msg + " Please do not share OTP.")[:500]],
                    "modus_operandi": "Seeded demo pattern for hackathon judging.",
                    "source": "demo_seed",
                    "embedding": Vector(embedding),
                    "embedding_source_text": msg,
                    "embedding_model": f"demo-random-{embed_dim}",
                    "embedding_updated_at": _iso(now),
                }
                ref = db.collection(FRAUD_PATTERNS).document(doc_id)
                batch.set(ref, payload, merge=True)
                writes += 1
                ops_in_batch += 1

            if do_cases:
                case_id = f"demo_case_{i:04d}"
                case_doc = {
                    "acknowledgment_id": case_id,
                    "timestamp": _iso(dt),
                    "scam_type": scam_type,
                    "risk_level": "HIGH" if severity in {"HIGH", "CRITICAL"} else "MEDIUM",
                    "confidence": rng.randint(55, 95),
                    "golden_hour_active": False,
                    "input_type": "text",
                    "summary": f"Seeded demo case: {scam_type}.",
                    "source": "demo_seed",
                }
                ref = db.collection(CASES).document(case_id)
                batch.set(ref, case_doc, merge=True)
                writes += 1
                ops_in_batch += 1

            i += 1
            maybe_commit()

    if ops_in_batch:
        maybe_commit(force=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed Firestore with demo historical cases/patterns for hackathon UI.")
    ap.add_argument("--count", type=int, default=847, help="Number of demo records to write (default: 847)")
    ap.add_argument("--seed", type=int, default=1337, help="PRNG seed (default: 1337)")
    ap.add_argument(
        "--batch-size",
        type=int,
        default=int(os.getenv("SATARK_SEED_BATCH_SIZE", "200")),
        help="Firestore batch commit size (ops). Lower this to avoid DEADLINE_EXCEEDED (default: 200)",
    )
    ap.add_argument(
        "--start-index",
        type=int,
        default=0,
        help="Starting index for deterministic doc IDs (useful for chunked seeding runs; default: 0)",
    )
    ap.add_argument(
        "--embed-dim",
        type=int,
        default=int(os.getenv("EMBEDDING_DIMENSION", "768")),
        help="Embedding vector dimension (default: EMBEDDING_DIMENSION or 768)",
    )
    ap.add_argument("--patterns", action="store_true", help="Seed fraud_patterns (default: on)")
    ap.add_argument("--cases", action="store_true", help="Seed cases (default: on)")
    ap.add_argument("--dry-run", action="store_true", help="Compute payloads without writing")
    args = ap.parse_args()

    do_patterns = args.patterns or (not args.patterns and not args.cases)
    do_cases = args.cases or (not args.patterns and not args.cases)

    seed_firestore(
        count=max(0, int(args.count)),
        seed=int(args.seed),
        embed_dim=max(8, int(args.embed_dim)),
        do_patterns=bool(do_patterns),
        do_cases=bool(do_cases),
        dry_run=bool(args.dry_run),
        batch_size=max(1, int(args.batch_size)),
        start_index=max(0, int(args.start_index)),
    )

    mode = "DRY RUN" if args.dry_run else "DONE"
    what = []
    if do_patterns:
        what.append("fraud_patterns")
    if do_cases:
        what.append("cases")
    print(f"{mode}: seeded {args.count} demo records into {', '.join(what)}")


if __name__ == "__main__":
    main()
