"""Unique payout references, preserving receipt IDs and all financial data."""

import re
from datetime import datetime


NUMBER_PATTERN = re.compile(r"^SP-(\d{6})-(\d+)$")


def payout_number(receipt_id, now=None):
    return f"SP-{(now or datetime.now()).strftime('%Y%m')}-{receipt_id:04d}"


def payout_number_repair_plan(rows, now=None):
    now = now or datetime.now()
    ids = [row.get("id") for row in rows]
    if any(type(value) is not int or value <= 0 for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("Payout receipt IDs must be unique positive integers before repairing their numbers.")
    groups = {}
    reserved = set()
    floor = max(ids, default=0)
    for row in rows:
        number = row.get("payout_number")
        groups.setdefault(number, []).append(row)
        if number:
            reserved.add(number)
            match = NUMBER_PATTERN.fullmatch(str(number))
            if match:
                floor = max(floor, int(match[2]))
    replacements = []
    for number, group in groups.items():
        if number and len(group) == 1:
            continue
        ordered = sorted(group, key=lambda row: row["id"])
        match = NUMBER_PATTERN.fullmatch(str(number or ""))
        keeper = next((row for row in ordered if match and row["id"] == int(match[2])), ordered[0]) if number else None
        for row in ordered:
            if row is keeper:
                continue
            created = row.get("created_at")
            month = match[1] if match else (str(created)[:7].replace("-", "") if created else now.strftime("%Y%m"))
            if not re.fullmatch(r"\d{6}", month):
                month = now.strftime("%Y%m")
            sequence = row["id"]
            replacement = f"SP-{month}-{sequence:04d}"
            while replacement in reserved:
                floor += 1
                sequence = floor
                replacement = f"SP-{month}-{sequence:04d}"
            reserved.add(replacement)
            floor = max(floor, sequence)
            replacements.append({"id": row["id"], "old_number": number, "new_number": replacement})
    return sorted(replacements, key=lambda item: item["id"]), floor


def ensure_payout_numbering(db, now=None):
    now = now or datetime.now()
    rows = list(db.stakeholder_payout_receipts.find({}, {"id": 1, "payout_number": 1, "created_at": 1}))
    plan, floor = payout_number_repair_plan(rows, now)
    repaired = []
    for change in plan:
        update = {"$set": {"payout_number": change["new_number"], "payout_number_repaired_at": now}}
        if change["old_number"]:
            update["$addToSet"] = {"previous_payout_numbers": change["old_number"]}
        result = db.stakeholder_payout_receipts.update_one(
            {"id": change["id"], "payout_number": change["old_number"]}, update,
        )
        if result.modified_count:
            repaired.append(change)
        # Links are by receipt ID, so duplicate old references cannot cross-update other receipts.
        db.payables.update_many({
            "source_module": {"$in": ["Stakeholder Payout", "Channel Partner Payout"]},
            "source_id": change["id"], "source_reference": change["old_number"],
        }, {"$set": {"source_reference": change["new_number"]}})
    db.counters.update_one({"_id": "stakeholder_payout_receipts"}, {"$max": {"sequence_value": floor}}, upsert=True)
    indexes = db.stakeholder_payout_receipts.index_information()
    for field, name in (("id", "unique_payout_receipt_id"), ("payout_number", "unique_payout_receipt_number")):
        if not any(index.get("unique") and index.get("key") == [(field, 1)] for index in indexes.values()):
            # Older deployments have non-unique id_1 indexes. Keep them and use
            # a distinct name for the unique constraint instead of replacing them.
            db.stakeholder_payout_receipts.create_index(field, unique=True, name=name)
    return repaired
