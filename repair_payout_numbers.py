"""Preview duplicate payout-number corrections, or apply them with --apply."""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient

from payout_numbering import ensure_payout_numbering, payout_number_repair_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", type=Path, help="Save the reference-only repair plan before applying changes.")
    args = parser.parse_args()
    load_dotenv(Path(__file__).with_name('.env'))
    client = MongoClient(os.environ["MONGO_DB_URI"], serverSelectionTimeoutMS=10000)
    db = client.get_database("lms_crm")
    rows = list(db.stakeholder_payout_receipts.find({}, {"id": 1, "payout_number": 1, "created_at": 1}))
    plan, floor = payout_number_repair_plan(rows)
    report = {"repairs": plan, "minimum_counter": floor, "applied": False}
    if args.backup:
        args.backup.write_text(json.dumps({"created_at": datetime.now().isoformat(), **report}, indent=2))
    if args.apply:
        report["repairs"] = ensure_payout_numbering(db)
        report["applied"] = True
    print(json.dumps(report, indent=2))
    client.close()


if __name__ == "__main__":
    main()
