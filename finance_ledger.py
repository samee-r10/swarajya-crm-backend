"""Small ledger rows enriched with batched reads instead of per-row joins."""


LEDGER_FIELDS = (
    "id", "display_id", "transaction_number", "transaction_date", "date",
    "created_at", "updated_at", "type", "status", "description", "category",
    "currency", "amount", "total_amount", "cgst_amount", "sgst_amount", "igst_amount",
    "tds_amount", "reference", "account_id", "customer_id", "vendor_id",
    "project_id", "invoice_id", "invoice_number", "payment_status",
)


def load_ledger_transactions(db, match):
    projection = {field: 1 for field in LEDGER_FIELDS}
    projection["_id"] = 0
    rows = list(db.transactions.find(match, projection))
    if not rows:
        return rows

    relations = (
        ("accounts", "account_id", {"name": "account_name", "gl_code": "gl_code"}),
        ("customers", "customer_id", {"company_name": "customer_name"}),
        ("vendors", "vendor_id", {"name": "vendor_name"}),
        ("projects", "project_id", {"project_name": "project_name"}),
        ("invoices", "invoice_id", {"invoice_number": "invoice_number"}),
    )
    for collection_name, foreign_key, fields in relations:
        ids = list({row[foreign_key] for row in rows if row.get(foreign_key) is not None})
        if not ids:
            continue
        related_projection = {"_id": 0, "id": 1, **{field: 1 for field in fields}}
        related = {
            item["id"]: item
            for item in db[collection_name].find({"id": {"$in": ids}}, related_projection)
        }
        for row in rows:
            item = related.get(row.get(foreign_key), {})
            for source, target in fields.items():
                if item.get(source) is not None:
                    row[target] = item[source]

    for row in rows:
        row["transaction_date"] = row.get("transaction_date") or row.get("date")
        row["gl_account_number"] = row.get("gl_code")
        row["gl_account_name"] = row.get("account_name")
    return rows
