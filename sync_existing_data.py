import sys
import os

sys.path.append("/Users/mishra/Documents/LMS-CRM/Backend")
from app import get_db, auto_process_treasury_split, fetch_all, fetch_one

def main():
    print("Starting sync of existing income transactions...")
    with get_db() as conn:
        # 1. Fetch all paid invoices (Skipped to avoid duplicate logging, transactions are now single source of truth)
        print("Skipping invoice sync to avoid duplicate logs (transactions are the single source of truth).")

        # 2. Fetch all income transactions
        transactions = fetch_all(
            "SELECT id, total_amount, project_id, transaction_date, description, category FROM transactions WHERE type = 'Income'"
        )
        print(f"Found {len(transactions)} income transactions.")
        for tx in transactions:
            category = tx.get("category") or "Sales Revenue"
            desc = f"Auto split from Income Transaction: {tx.get('description') or ''}"
            # Check if this transaction split is already recorded in treasury_revenue
            existing = fetch_one(
                "SELECT id FROM treasury_revenue WHERE description = %s AND amount = %s",
                (desc, float(tx["total_amount"]))
            )
            if not existing:
                print(f"Importing transaction {tx['id']} for ₹{tx['total_amount']} ({tx.get('description') or ''})...")
                auto_process_treasury_split(
                    amount=float(tx["total_amount"]),
                    project_id=tx["project_id"],
                    revenue_type="Sales Income" if category == "Sales Revenue" else "Other Income",
                    entry_date=tx["transaction_date"],
                    description=desc,
                    transaction_id=tx["id"]
                )
            else:
                print(f"Transaction {tx['id']} already imported.")
    print("Sync complete!")

if __name__ == "__main__":
    main()
