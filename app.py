import json
import mimetypes
import os
import re
import hmac
from base64 import urlsafe_b64encode
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal
from hashlib import sha256
import hashlib
import urllib.error
import urllib.parse
import urllib.request
# sameer
import pymongo
from bson import ObjectId
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pymongo.errors import ConnectionFailure
from dotenv import dotenv_values, load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.security import check_password_hash as werkzeug_check_password_hash
from werkzeug.security import generate_password_hash as werkzeug_generate_password_hash
from werkzeug.local import LocalProxy


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "Frontend")

# Load .env from backend dir first, then project root as fallback
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5173")

app = Flask(
    __name__,
    template_folder=os.path.join(FRONTEND_DIR, "templates"),
    static_folder=os.path.join(FRONTEND_DIR, "static"),
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# ── CORS ──────────────────────────────────────────────────────────────────────
# Allow requests from local dev AND the production Vercel frontend domain.
# supports_credentials=True is required so session cookies work across origins.
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    FRONTEND_URL,
    "https://swarajya-crm-frontend.vercel.app",
    "https://crm.swarajyaconsultancy.in"
]
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

# ── Session cookie settings ────────────────────────────────────────────────────
# Production Vercel apps are cross-site and need SameSite=None + Secure.
# Local Vite dev uses an HTTP proxy, so Secure cookies would be dropped by the browser.
IS_PRODUCTION = bool(os.getenv("VERCEL")) or os.getenv("FLASK_ENV") == "production"
app.config["SESSION_COOKIE_SAMESITE"] = "None" if IS_PRODUCTION else "Lax"
app.config["SESSION_COOKIE_SECURE"] = IS_PRODUCTION
app.config["SESSION_COOKIE_HTTPONLY"] = True


# ── Health check ───────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/api/health")
def health_check():
    mongo_uri_set = bool(os.getenv("MONGO_DB_URI"))
    try:
        db = get_db()
        db.command("ping")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    return jsonify({
        "status": "ok",
        "service": "Swarajya CRM Backend",
        "mongo_uri_configured": mongo_uri_set,
        "database": db_status
    })


VAULT_CATEGORIES = [
    "Client Credential",
    "Company Credential",
    "Infrastructure",
    "Finance & Banking",
    "Vendor / Partner",
    "Other",
]

CUSTOMER_STATUSES = ["Lead", "Active", "Inactive"]
OPPORTUNITY_STAGES = ["Draft", "Discussion", "Commercial negotiation", "Contractual negotiation", "DA Signed", "Lost to competitor", "Rejected by SC", "Lost"]
PROJECT_STATUSES = ["Planning", "In Progress", "Blocked", "Delivered", "On Hold"]
FIELD_TYPES = ["Text", "Long Text", "Number", "Date", "Checkbox", "Dropdown"]
SETUP_HIDDEN_OBJECT_API_NAMES = {"accounts"}
VENDOR_CATEGORIES = {"Supply", "Service", "Both"}
REGISTRATION_TYPES = {"Registered", "Not Registered"}
SUPPLIER_CATEGORIES = {"MSME", "Non-MSME"}
MASTER_OPTION_CONFIG = {
    "payment-terms": {
        "collection": "payment_terms",
        "counter": "payment_terms",
        "response_key": "payment_terms",
        "label": "Payment Term",
        "defaults": ["Advance", "30 Days"],
    },
    "payment-modes": {
        "collection": "payment_modes",
        "counter": "payment_modes",
        "response_key": "payment_modes",
        "label": "Payment Mode",
        "defaults": ["Bank Transfer", "UPI", "Cheque", "Cash"],
    },
}
EXPENSE_CLAIM_STATUSES = {
    "Draft",
    "Submitted",
    "Pending Stakeholder Approval",
    "Pending Approval Sequence 1",
    "Pending Approval Sequence 2",
    "Pending Approval Sequence 3",
    "Under Review",
    "Approved",
    "Rejected",
    "Posted",
    "Settled",
    "Cancelled",
}
CLAIM_EDITABLE_STATUSES = {"Draft"}
LOAN_STATUSES = {"Draft", "Active", "Closed", "Cancelled"}
LOAN_PROVIDER_TYPES = {"Bank", "Stakeholder", "Third-Party Agency", "Other"}
LOAN_INTEREST_TYPES = {"Fixed", "Floating"}
LOAN_TENURE_UNITS = {"Months", "Years"}
LOAN_REPAYMENT_FREQUENCIES = {"Monthly", "Quarterly", "Half-Yearly", "Yearly", "Custom"}
LOAN_SCHEDULE_STATUSES = {"Unpaid", "Paid", "Overdue", "Partially Paid"}
STAKEHOLDER_PAYOUT_TYPES = {"Profit Distribution", "Dividend", "Capital Return", "Custom", "Channel Partner Payout", "Channel Partner Commission"}
PAYOUT_RECIPIENT_TYPES = {"Stakeholder", "Channel Partner"}
STAKEHOLDER_PAYOUT_STATUSES = {
    "Draft",
    "Pending Stakeholder Approval",
    "Pending Approval Sequence 1",
    "Pending Approval Sequence 2",
    "Pending Approval Sequence 3",
    "Approved",
    "Pending Payment",
    "Partially Paid",
    "Paid",
    "Rejected",
    "Cancelled",
}


def _check_scrypt_password_hash(pwhash, password):
    method, salt, hashval = pwhash.split("$", 2)
    _, n, r, p = method.split(":")
    kdf = Scrypt(salt=salt.encode(), length=len(bytes.fromhex(hashval)), n=int(n), r=int(r), p=int(p))
    candidate = kdf.derive(password.encode()).hex()
    return hmac.compare_digest(candidate, hashval)


def check_password_hash(pwhash, password):
    try:
        return werkzeug_check_password_hash(pwhash, password)
    except AttributeError as exc:
        if "scrypt" in str(exc) and pwhash.startswith("scrypt:"):
            return _check_scrypt_password_hash(pwhash, password)
        raise


def generate_password_hash(password):
    method = os.getenv("PASSWORD_HASH_METHOD")
    if not method:
        method = "scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2:sha256:1000000"
    return werkzeug_generate_password_hash(password, method=method)

def get_active_currencies():
    try:
        row = fetch_one("SELECT setting_value FROM system_settings WHERE setting_key = 'currencies'")
        if row and row["setting_value"]:
            return json.loads(row["setting_value"])
    except Exception:
        pass
    return [
        {"code": "USD", "symbol": "$"},
        {"code": "INR", "symbol": "\u20b9"},
        {"code": "EUR", "symbol": "\u20ac"},
        {"code": "GBP", "symbol": "\u00a3"}
    ]


def get_currency_symbols_dict():
    return {c["code"]: c["symbol"] for c in get_active_currencies()}


CURRENCIES = LocalProxy(lambda: get_active_currencies())
CURRENCY_SYMBOLS = LocalProxy(lambda: get_currency_symbols_dict())
PUBLIC_ENDPOINTS = {"login", "api_auth_login", "static"}


mongo_client = None

def get_db():
    global mongo_client
    if mongo_client is None:
        uri = os.getenv("MONGO_DB_URI")
        if not uri:
            raise ValueError("MONGO_DB_URI is not set in .env")
        mongo_client = pymongo.MongoClient(uri)
    # The database name is parsed from the URI or defaults to 'lms_crm' if not in URI.
    # Actually for Atlas standard connection string, you specify db after /
    return mongo_client.get_database("lms_crm")

def get_next_sequence_value(sequence_name):
    db = get_db()
    # Find the sequence document and increment the sequence value by 1.
    # If the document does not exist, it will be created and the sequence value will be 1.
    sequence_doc = db.counters.find_one_and_update(
        {"_id": sequence_name},
        {"$inc": {"sequence_value": 1}},
        upsert=True,
        return_document=pymongo.ReturnDocument.AFTER
    )
    return sequence_doc["sequence_value"]

def fetch_all(query, params=None):
    raise NotImplementedError("fetch_all is deprecated. Use PyMongo direct queries.")

def fetch_one(query, params=None):
    raise NotImplementedError("fetch_one is deprecated. Use PyMongo direct queries.")

def execute(query, params=None):
    raise NotImplementedError("execute is deprecated. Use PyMongo direct queries.")


def json_ready(value):
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    return value


def cloudinary_config():
    dotenv_config = dotenv_values(os.path.join(BASE_DIR, ".env"))
    cloudinary_url = os.getenv("CLOUDINARY_URL") or dotenv_config.get("CLOUDINARY_URL")
    parsed_url = urllib.parse.urlparse(cloudinary_url or "")
    url_config = {}
    if parsed_url.scheme == "cloudinary" and parsed_url.hostname:
        url_config = {
            "cloud_name": parsed_url.hostname,
            "api_key": parsed_url.username,
            "api_secret": parsed_url.password,
        }
    return {
        "cloud_name": os.getenv("CLOUDINARY_CLOUD_NAME") or dotenv_config.get("CLOUDINARY_CLOUD_NAME") or url_config.get("cloud_name"),
        "api_key": os.getenv("CLOUDINARY_API_KEY") or dotenv_config.get("CLOUDINARY_API_KEY") or url_config.get("api_key"),
        "api_secret": os.getenv("CLOUDINARY_API_SECRET") or dotenv_config.get("CLOUDINARY_API_SECRET") or url_config.get("api_secret"),
    }


def is_cloudinary_configured():
    config = cloudinary_config()
    return all(config.values())


def multipart_encode(fields, files):
    boundary = f"----swarajya-crm-{datetime.now().timestamp()}".replace(".", "")
    body = bytearray()
    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        body.extend(str(value).encode())
        body.extend(b"\r\n")
    for name, file_info in files.items():
        filename = file_info["filename"]
        content_type = file_info["content_type"]
        content = file_info["content"]
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode())
        body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def upload_file_to_cloudinary(file_storage, folder="crm-documents"):
    if not is_cloudinary_configured():
        raise ValueError("Cloudinary is not configured for this backend process. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in the backend environment, or set CLOUDINARY_URL, then restart the backend.")
    if not file_storage or not file_storage.filename:
        raise ValueError("Select a document to upload.")

    file_bytes = file_storage.read()
    if not file_bytes:
        raise ValueError("Selected document is empty.")
    max_size = 12 * 1024 * 1024
    if len(file_bytes) > max_size:
        raise ValueError("Document must be 12 MB or smaller.")

    config = cloudinary_config()
    safe_folder = re.sub(r"[^a-zA-Z0-9/_-]+", "-", folder).strip("-") or "crm-documents"
    timestamp = int(datetime.now().timestamp())
    signed_params = {
        "folder": safe_folder,
        "timestamp": timestamp,
        "unique_filename": "true",
        "use_filename": "true",
    }
    signature_base = "&".join(f"{key}={signed_params[key]}" for key in sorted(signed_params))
    signature = hashlib.sha1(f"{signature_base}{config['api_secret']}".encode()).hexdigest()
    fields = {
        **signed_params,
        "api_key": config["api_key"],
        "signature": signature,
    }
    content_type = file_storage.content_type or mimetypes.guess_type(file_storage.filename)[0] or "application/octet-stream"
    payload, multipart_type = multipart_encode(fields, {
        "file": {
            "filename": file_storage.filename,
            "content_type": content_type,
            "content": file_bytes,
        }
    })
    upload_url = f"https://api.cloudinary.com/v1_1/{config['cloud_name']}/auto/upload"
    request_obj = urllib.request.Request(upload_url, data=payload, headers={"Content-Type": multipart_type}, method="POST")
    try:
        with urllib.request.urlopen(request_obj, timeout=30) as response:
            uploaded = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="ignore")
        raise ValueError(f"Cloudinary upload failed: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Cloudinary upload failed: {exc.reason}") from exc

    return {
        "name": file_storage.filename,
        "type": content_type,
        "size": uploaded.get("bytes", len(file_bytes)),
        "secure_url": uploaded.get("secure_url"),
        "url": uploaded.get("secure_url") or uploaded.get("url"),
        "public_id": uploaded.get("public_id"),
        "resource_type": uploaded.get("resource_type"),
        "format": uploaded.get("format"),
        "width": uploaded.get("width"),
        "height": uploaded.get("height"),
        "created_at": datetime.now(),
        "provider": "cloudinary",
    }


def slugify_api_name(value, suffix=""):
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    slug = re.sub(r"_+", "_", slug)
    if suffix and not slug.endswith(suffix):
        slug = f"{slug}{suffix}"
    return slug



def get_fields_for_user(object_id):
    db = get_db()
    fields = list(db.custom_fields.find({"object_id": object_id}, {"_id": 0}).sort("is_native", -1))
    user = get_current_user()
    if not user or not user.get("role_id"):
        return fields
        
    role_id = user["role_id"]
    fls = list(db.field_level_security.find({"role_id": role_id, "object_id": object_id}))
    if not fls:
        # Default is can_view=True, can_edit=True
        for f in fields:
            f["can_edit"] = True
        return fields
        
    fls_map = {item["field_id"]: item for item in fls}
    
    filtered_fields = []
    for f in fields:
        sec = fls_map.get(f["id"])
        if sec:
            if sec.get("can_view"):
                f["can_edit"] = bool(sec.get("can_edit"))
                filtered_fields.append(f)
        else:
            f["can_edit"] = True
            filtered_fields.append(f)
            
    return filtered_fields


def custom_objects_for_nav():
    try:
        return fetch_all("SELECT label, plural_label, api_name FROM custom_objects WHERE is_standard = 0 ORDER BY plural_label")
    except Error:
        return []


def app_launcher_items():
    items = [
        {"label": "Dashboard", "type": "App", "url": url_for("dashboard")},
        {"label": "Customers", "type": "Standard Object", "url": url_for("customers")},
        {"label": "Opportunities", "type": "Standard Object", "url": url_for("opportunities")},
        {"label": "Projects", "type": "Module", "url": url_for("projects_module")},
        {"label": "Finance", "type": "Module", "url": url_for("finance_dashboard")},
    ]
    for custom_object in custom_objects_for_nav():
        items.append(
            {
                "label": custom_object["plural_label"],
                "type": "Custom Object",
                "url": url_for("custom_object_records", api_name=custom_object["api_name"]),
            }
        )
    return items


def get_standard_fields(api_name):
    custom_object = fetch_one("SELECT * FROM custom_objects WHERE api_name = %s", (api_name,))
    if not custom_object:
        return [], None
    fields = fetch_all(
        "SELECT * FROM custom_fields WHERE object_id = %s AND is_native = 0 ORDER BY created_at",
        (custom_object["id"],),
    )
    return fields, custom_object


def get_object_fields(api_name):
    custom_object = fetch_one("SELECT * FROM custom_objects WHERE api_name = %s", (api_name,))
    if not custom_object:
        return [], None
    fields = fetch_all(
        "SELECT * FROM custom_fields WHERE object_id = %s ORDER BY is_native DESC, id",
        (custom_object["id"],),
    )
    return fields, custom_object


def seed_native_standard_fields():
    db = get_db()
    native_fields = {
        "customers": [
            ("Company Name", "company_name", "Text", 1),
            ("Contact Name", "contact_name", "Text", 1),
            ("Email", "email", "Text", 0),
            ("Phone", "phone", "Text", 0),
            ("Industry", "industry", "Text", 0),
            ("Status", "status", "Dropdown", 1, '["Lead", "Active", "Inactive"]'),
            ("Notes", "notes", "Long Text", 0),
            ("Billing Address", "billing_address", "Long Text", 0),
        ],
        "opportunities": [
            ("Customer", "customer_id", "Number", 1),
            ("Title", "title", "Text", 1),
            ("Opportunity Number", "opportunity_number", "Text", 0),
            ("Value", "value", "Number", 0),
            ("Currency", "currency", "Text", 1),
            ("Stage", "stage", "Text", 1),
            ("Expected Close", "expected_close", "Date", 0),
            ("Requirements", "requirements", "Long Text", 0),
            ("Next Action", "next_action", "Text", 0),
        ],
        "projects": [
            ("Customer", "customer_id", "Number", 1),
            ("Opportunity", "opportunity_id", "Number", 1),
            ("Project Name", "project_name", "Text", 1),
            ("Status", "status", "Dropdown", 1, '["Planning", "In Progress", "Blocked", "Delivered", "On Hold"]'),
            ("Client Requirements", "client_requirements", "Long Text", 0),
            ("Delivery Timeline", "delivery_timeline", "Date", 0),
            ("Product Delivery Status", "product_delivery_status", "Text", 0),
            ("Owner", "owner", "Text", 0),
            ("Latest Update", "last_update", "Long Text", 0),
        ],
        "vendors": [
            ("Name", "name", "Text", 1),
            ("Contact Person", "contact_person", "Text", 0),
            ("Email", "email", "Text", 0),
            ("Phone", "phone", "Text", 0),
            ("Category", "category", "Text", 0),
            ("Notes", "notes", "Long Text", 0),
        ],
        "transactions": [
            ("Transaction Date", "transaction_date", "Date", 1),
            ("Amount", "amount", "Number", 1),
            ("Currency", "currency", "Text", 1),
            ("Type", "type", "Dropdown", 1, '["Income", "Expense"]'),
            ("Account", "account_id", "Number", 1),
            ("Customer", "customer_id", "Number", 0),
            ("Vendor", "vendor_id", "Number", 0),
            ("Category", "category", "Text", 0),
            ("Description", "description", "Long Text", 0),
            ("CGST Percent", "cgst_percent", "Number", 0),
            ("CGST Amount", "cgst_amount", "Number", 0),
            ("IGST Percent", "igst_percent", "Number", 0),
            ("IGST Amount", "igst_amount", "Number", 0),
            ("TDS Percent", "tds_percent", "Number", 0),
            ("TDS Amount", "tds_amount", "Number", 0),
            ("Total Amount", "total_amount", "Number", 1),
            ("Project", "project_id", "Number", 0),
        ],
    }
    for object_api_name, fields in native_fields.items():
        obj = db.custom_objects.find_one({"api_name": object_api_name})
        if not obj:
            continue
        object_id = obj["id"]
        for f in fields:
            label = f[0]
            api_name = f[1]
            field_type = f[2]
            is_required = f[3]
            picklist_options = f[4] if len(f) > 4 else None
            
            existing = db.custom_fields.find_one({"object_id": object_id, "api_name": api_name})
            if not existing:
                db.custom_fields.insert_one({
                    "id": get_next_sequence_value("custom_fields"),
                    "object_id": object_id,
                    "label": label,
                    "api_name": api_name,
                    "is_native": 1,
                    "native_column": api_name,
                    "field_type": field_type,
                    "is_required": is_required,
                    "picklist_options": picklist_options,
                    "created_at": datetime.now()
                })


def remove_hidden_setup_object_metadata(db):
    hidden_objects = list(db.custom_objects.find({"api_name": {"$in": list(SETUP_HIDDEN_OBJECT_API_NAMES)}}))
    hidden_object_ids = [obj["id"] for obj in hidden_objects]
    if not hidden_object_ids:
        return
    db.custom_fields.delete_many({"object_id": {"$in": hidden_object_ids}})
    db.field_level_security.delete_many({"object_id": {"$in": hidden_object_ids}})
    db.custom_objects.delete_many({"id": {"$in": hidden_object_ids}})


DEFAULT_ACCOUNTS = [
    {"name": "Cash on Hand", "gl_code": "1000", "type": "Asset"},
    {"name": "Bank Account", "gl_code": "1010", "type": "Asset"},
    {"name": "Sales Revenue", "gl_code": "4000", "type": "Revenue"},
    {"name": "Subscription Revenue", "gl_code": "4010", "type": "Revenue"},
    {"name": "Operating Expenses", "gl_code": "5000", "type": "Expense"},
    {"name": "Salary", "gl_code": "5010", "type": "Expense"},
    {"name": "Stakeholder Payout", "gl_code": "5020", "type": "Expense"},
    {"name": "Channel Partner Payout", "gl_code": "5030", "type": "Expense"},
    {"name": "Employee Claims", "gl_code": "7010", "type": "Expense"},
]


def ensure_default_accounts(db):
    for account in DEFAULT_ACCOUNTS:
        existing = db.accounts.find_one({"name": account["name"]})
        visibility = default_account_visibility(account["type"])
        if existing:
            updates = {}
            if not existing.get("gl_code"):
                updates["gl_code"] = account["gl_code"]
            if not existing.get("type"):
                updates["type"] = account["type"]
            if "is_active" not in existing:
                updates["is_active"] = 1
            if "show_in_income" not in existing:
                updates["show_in_income"] = visibility["show_in_income"]
            if "show_in_expense" not in existing:
                updates["show_in_expense"] = visibility["show_in_expense"]
            if updates:
                db.accounts.update_one({"id": existing["id"]}, {"$set": updates})
        else:
            db.accounts.insert_one({
                "id": get_next_sequence_value("accounts"),
                "gl_code": account["gl_code"],
                "name": account["name"],
                "type": account["type"],
                "is_active": 1,
                **visibility,
                "balance": 0,
                "is_system_default": 1,
                "created_at": datetime.now()
            })

    for account in db.accounts.find({"$or": [
        {"is_active": {"$exists": False}},
        {"show_in_income": {"$exists": False}},
        {"show_in_expense": {"$exists": False}},
    ]}):
        visibility = default_account_visibility(account.get("type"))
        updates = {}
        if "is_active" not in account:
            updates["is_active"] = 1
        if "show_in_income" not in account:
            updates["show_in_income"] = visibility["show_in_income"]
        if "show_in_expense" not in account:
            updates["show_in_expense"] = visibility["show_in_expense"]
        if updates:
            db.accounts.update_one({"id": account["id"]}, {"$set": updates})


def init_database():
    db = get_db()
    
    # Initialize basic collections
    collections = db.list_collection_names()
    if "counters" not in collections:
        db.create_collection("counters")
        
    # Seed custom objects
    remove_hidden_setup_object_metadata(db)

    standard_objects = [
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Customer', 'plural_label': 'Customers', 'api_name': 'customers', 'is_standard': 1, 'storage_table': 'customers', 'description': 'Standard customer object.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Opportunity', 'plural_label': 'Opportunities', 'api_name': 'opportunities', 'is_standard': 1, 'storage_table': 'opportunities', 'description': 'Standard sales opportunity object.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Project', 'plural_label': 'Projects', 'api_name': 'projects', 'is_standard': 1, 'storage_table': 'projects', 'description': 'Standard delivery project object.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Vendor', 'plural_label': 'Vendors', 'api_name': 'vendors', 'is_standard': 1, 'storage_table': 'vendors', 'description': 'Standard vendor object for finance.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Transaction', 'plural_label': 'Transactions', 'api_name': 'transactions', 'is_standard': 1, 'storage_table': 'transactions', 'description': 'Standard transaction object for finance.', 'created_at': datetime.now()}
    ]
    for obj in standard_objects:
        if not db.custom_objects.find_one({"api_name": obj["api_name"]}):
            db.custom_objects.insert_one(obj)

    # Seed native fields
    seed_native_standard_fields()

    # Seed system settings
    if not db.system_settings.find_one({"setting_key": "currencies"}):
        db.system_settings.insert_one({
            "setting_key": "currencies",
            "setting_value": json.dumps([
                {"code": "USD", "symbol": "$"},
                {"code": "INR", "symbol": "₹"},
                {"code": "EUR", "symbol": "€"},
                {"code": "GBP", "symbol": "£"}
            ])
        })

    # Seed accounts
    if db.accounts.count_documents({}) == 0:
        db.accounts.insert_many([
            {"id": get_next_sequence_value("accounts"), "gl_code": "1000", "name": "Cash on Hand", "type": "Asset", "balance": 0, "is_system_default": 1, "created_at": datetime.now()},
            {"id": get_next_sequence_value("accounts"), "gl_code": "1010", "name": "Bank Account", "type": "Asset", "balance": 0, "is_system_default": 1, "created_at": datetime.now()},
            {"id": get_next_sequence_value("accounts"), "gl_code": "4000", "name": "Sales Revenue", "type": "Revenue", "balance": 0, "is_system_default": 1, "created_at": datetime.now()},
            {"id": get_next_sequence_value("accounts"), "gl_code": "5000", "name": "Operating Expenses", "type": "Expense", "balance": 0, "is_system_default": 1, "created_at": datetime.now()}
        ])

    ensure_default_accounts(db)

    # Seed roles
    if db.roles.count_documents({}) == 0:
        db.roles.insert_one({"id": get_next_sequence_value("roles"), "name": "Admin", "description": "Full access", "created_at": datetime.now()})
        db.roles.insert_one({"id": get_next_sequence_value("roles"), "name": "Standard", "description": "Standard access", "created_at": datetime.now()})

    # Seed Admin User
    admin_role = db.roles.find_one({"name": "Admin"})
    if not db.app_users.find_one({"email": "system.administrator@swarajyaconsultancy.in"}):
        db.app_users.insert_one({
            "id": get_next_sequence_value("app_users"),
            "full_name": "System Administrator",
            "email": "system.administrator@swarajyaconsultancy.in",
            "password_hash": generate_password_hash("change123"),
            "role_id": admin_role["id"] if admin_role else 1,
            "is_active": 1,
            "has_treasury_access": 1,
            "has_finance_access": 1,
            "has_vault_access": 1,
            "created_at": datetime.now()
        })
    else:
        # Ensure password is set
        admin = db.app_users.find_one({"email": "system.administrator@swarajyaconsultancy.in"})
        if not admin.get("password_hash"):
            db.app_users.update_one({"_id": admin["_id"]}, {"$set": {"password_hash": generate_password_hash("change123")}})
        db.app_users.update_one(
            {"_id": admin["_id"]},
            {"$set": {"has_treasury_access": 1, "has_finance_access": 1, "has_vault_access": 1}},
        )

    # Backfill module access flags for databases created before these modules existed.
    db.app_users.update_many({"has_treasury_access": {"$exists": False}}, {"$set": {"has_treasury_access": 0}})
    db.app_users.update_many({"has_finance_access": {"$exists": False}}, {"$set": {"has_finance_access": 0}})
    db.app_users.update_many({"has_vault_access": {"$exists": False}}, {"$set": {"has_vault_access": 0}})

    # Indexes
    db.app_users.create_index("email", unique=True)
    db.invoices.create_index("invoice_number", unique=True)
    db.treasury_revenue.create_index("revenue_id", unique=True)
    db.custom_objects.create_index("api_name", unique=True)
    db.vault_entries.create_index("category")
    db.vault_entries.create_index("title")
    db.bank_accounts.create_index("id", unique=True)


@app.template_filter("date_or_dash")
def date_or_dash(value):
    if not value:
        return "-"
    if isinstance(value, date):
        return value.strftime("%d %b %Y")
    return value


@app.errorhandler(pymongo.errors.PyMongoError)
def handle_db_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"error": str(error)}), 500
    return render_template("error.html", error=error), 500

def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.before_request
def force_password_change_check():
    if request.path.startswith("/api/") and request.path not in [
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/change-password",
        "/api/health"
    ]:
        user_id = session.get("user_id")
        if user_id:
            db = get_db()
            user = db.app_users.find_one({"id": user_id})
            if user and user.get("requires_password_change", False):
                return jsonify({"error": "Password change required", "requires_password_change": True}), 403

@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    
    db = get_db()
    user = db.app_users.find_one({"email": email})
    
    if user and check_password_hash(user.get("password_hash", ""), password):
        if not user.get("is_active", 1):
            return jsonify({"error": "Account is disabled"}), 403
            
        session["user_id"] = user["id"]
        
        role = db.roles.find_one({"id": user.get("role_id")})
        role_name = role["name"] if role else "Standard"
        is_admin = role_name in ["Admin", "System Administrator"]
        
        user_data = {
            "id": user["id"],
            "full_name": user.get("full_name"),
            "email": user.get("email"),
            "phone": user.get("phone", ""),
            "role_name": role_name,
            "is_active": 1 if user.get("is_active", 1) else 0,
            "has_treasury_access": 1 if is_admin else user.get("has_treasury_access", 0),
            "has_finance_access": 1 if is_admin else user.get("has_finance_access", 0),
            "has_vault_access": 1 if is_admin else user.get("has_vault_access", 0),
            "requires_password_change": bool(user.get("requires_password_change", False))
        }
        return jsonify({"user": user_data})
        
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/profile", methods=["GET", "PUT"])
def api_profile():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    user = db.app_users.find_one({"id": session["user_id"]})
    if not user:
        return jsonify({"error": "User not found"}), 404

    role = db.roles.find_one({"id": user.get("role_id")})
    role_name = role["name"] if role else "Standard"
    is_admin = role_name in ["Admin", "System Administrator"]

    if request.method == "PUT":
        data = request.get_json() or {}
        full_name = (data.get("full_name") or "").strip()
        phone = (data.get("phone") or "").strip()
        if not full_name:
            return jsonify({"error": "Full name is required"}), 400

        old_user = dict(user)
        db.app_users.update_one(
            {"id": user["id"]},
            {"$set": {
                "full_name": full_name,
                "phone": phone,
                "updated_at": datetime.now()
            }}
        )
        user = db.app_users.find_one({"id": session["user_id"]})
        log_activity_async("Setup", "User Profile", user["id"], "UPDATE", old_data=old_user, new_data=user, reference_number=user.get("email"))

    profile = {
        "id": user["id"],
        "full_name": user.get("full_name"),
        "email": user.get("email"),
        "phone": user.get("phone", ""),
        "role_name": role_name,
        "is_active": 1 if user.get("is_active", 1) else 0,
        "has_treasury_access": 1 if is_admin else user.get("has_treasury_access", 0),
        "has_finance_access": 1 if is_admin else user.get("has_finance_access", 0),
        "has_vault_access": 1 if is_admin else user.get("has_vault_access", 0),
        "requires_password_change": bool(user.get("requires_password_change", False))
    }
    return jsonify(json_ready({"user": profile}))


@app.route("/api/auth/change-password", methods=["POST"])
def api_auth_change_password():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    
    if not current_password or not new_password:
        return jsonify({"error": "Current and new passwords are required"}), 400
        
    db = get_db()
    user = db.app_users.find_one({"id": session["user_id"]})
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    if not check_password_hash(user.get("password_hash", ""), current_password):
        return jsonify({"error": "Incorrect current password"}), 400
        
    if check_password_hash(user.get("password_hash", ""), new_password):
        return jsonify({"error": "New password cannot be the same as the current password"}), 400
        
    is_valid, msg = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"error": msg}), 400
        
    db.app_users.update_one(
        {"id": session["user_id"]},
        {"$set": {
            "password_hash": generate_password_hash(new_password),
            "requires_password_change": False
        }}
    )
    return jsonify({"success": True})

def require_treasury_access():
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user = db.app_users.find_one({"id": session["user_id"]})
    if not user or not user.get("has_treasury_access"):
        abort(403)
    return user

def require_finance_access():
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user = db.app_users.find_one({"id": session["user_id"]})
    if not user or not user.get("has_finance_access"):
        abort(403)
    return user


def require_vault_access():
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user = db.app_users.find_one({"id": session["user_id"]})
    role = db.roles.find_one({"id": user.get("role_id")}) if user else None
    is_admin = role and role.get("name") in ["Admin", "System Administrator"]
    if not user or (not is_admin and not user.get("has_vault_access")):
        abort(403)
    return user


@app.route("/api/uploads/cloudinary", methods=["POST"])
def api_cloudinary_upload():
    require_finance_access()
    upload = request.files.get("file")
    folder_context = request.form.get("folder") or "finance-documents"
    try:
        document = upload_file_to_cloudinary(upload, f"swarajya-crm/{folder_context}")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(json_ready({"document": document}))


def require_vault_unlocked():
    user = require_vault_access()
    if not user.get("vault_access_code_hash"):
        return None, (jsonify({"error": "Vault access code is not set for this user."}), 403)
    if session.get("vault_unlocked_user_id") != user.get("id"):
        return None, (jsonify({"error": "Vault access code required."}), 423)
    return user, None


def _vault_serializer():
    secret = app.secret_key or os.getenv("FLASK_SECRET_KEY", "dev-secret-key")
    return URLSafeSerializer(str(secret), salt="vault-credentials-v1")


def _vault_fernet():
    secret = str(app.secret_key or os.getenv("FLASK_SECRET_KEY", "dev-secret-key"))
    key = urlsafe_b64encode(sha256(secret.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_vault_secret(value):
    if value is None or value == "":
        return ""
    encrypted = _vault_fernet().encrypt(str(value).encode("utf-8")).decode("utf-8")
    return f"fernet:{encrypted}"


def decrypt_vault_secret(token):
    if not token:
        return ""
    if token.startswith("fernet:"):
        try:
            return _vault_fernet().decrypt(token.removeprefix("fernet:").encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return ""
    try:
        return _vault_serializer().loads(token)
    except BadSignature:
        return ""


def serialize_vault_entry(doc, include_secrets=False):
    if not doc:
        return None
    entry = {k: v for k, v in doc.items() if k not in ("_id", "password_encrypted")}
    entry["has_password"] = bool(doc.get("password_encrypted"))
    if include_secrets:
        entry["password"] = decrypt_vault_secret(doc.get("password_encrypted", ""))
    else:
        entry.pop("password", None)
    return entry


def log_vault_action(user_id, action, details=""):
    db = get_db()
    db.vault_logs.insert_one({
        "id": get_next_sequence_value("vault_logs"),
        "user_id": user_id,
        "action": action,
        "details": details,
        "created_at": datetime.now(),
    })


def get_current_user():
    """Return the current logged-in user doc, or None if not authenticated."""
    if "user_id" not in session:
        return None
    db = get_db()
    return db.app_users.find_one({"id": session["user_id"]})


AUDIT_FIELD_KEYS = {
    "_id",
    "created_at",
    "updated_at",
    "modified_at",
    "created_by_id",
    "created_by_name",
    "updated_by_id",
    "updated_by_name",
    "modified_by_id",
    "modified_by_name",
}


def require_current_user():
    """Return the logged-in user for manual writes, or reject unauthenticated changes."""
    user = get_current_user()
    if not user:
        abort(401)
    return user


def audit_actor():
    user = require_current_user()
    return user, user["id"], user.get("full_name") or user.get("email") or "Unknown User"


def merge_client_fields(target, data, protected_keys=None):
    protected = set(protected_keys or set()) | AUDIT_FIELD_KEYS | {"id"}
    for key, value in (data or {}).items():
        if key not in target and key not in protected:
            target[key] = value
    return target

def log_treasury_action(user_id, action, details=""):
    db = get_db()
    db.treasury_logs.insert_one({
        "id": get_next_sequence_value("treasury_logs"),
        "user_id": user_id,
        "action": action,
        "details": details,
        "created_at": datetime.now()
    })


def get_settled_revenue_ids(db):
    return [
        doc["id"]
        for doc in db.treasury_revenue.find({"is_settled": True}, {"id": 1, "_id": 0})
    ]


def reserve_balance_payout_clause(settled_revenue_ids):
    """Match treasury payouts that count toward the company reserve balance."""
    return {
        "$or": [
            {"revenue_id": {"$exists": False}},
            {"revenue_id": None},
            {"revenue_id": {"$in": settled_revenue_ids}},
        ]
    }


def purge_unsettled_revenue_payouts(db):
    """Remove ledger payouts for revenue that has not been settled yet."""
    unsettled_ids = [
        doc["id"]
        for doc in db.treasury_revenue.find({"is_settled": {"$ne": True}}, {"id": 1, "_id": 0})
    ]
    if unsettled_ids:
        db.treasury_payouts.delete_many({"revenue_id": {"$in": unsettled_ids}})


def purge_orphaned_unsettled_transaction_revenue(db):
    """Remove unsettled treasury rows whose source transaction no longer exists."""
    synced_revenues = list(
        db.treasury_revenue.find(
            {
                "transaction_id": {"$exists": True, "$ne": None},
                "is_settled": {"$ne": True},
            },
            {"id": 1, "transaction_id": 1, "_id": 0},
        )
    )
    if not synced_revenues:
        return

    transaction_ids = [doc["transaction_id"] for doc in synced_revenues]
    existing_transaction_ids = {
        doc["id"]
        for doc in db.transactions.find({"id": {"$in": transaction_ids}}, {"id": 1, "_id": 0})
    }
    orphaned_revenue_ids = [
        doc["id"]
        for doc in synced_revenues
        if doc.get("transaction_id") not in existing_transaction_ids
    ]
    if orphaned_revenue_ids:
        db.treasury_revenue.delete_many({"id": {"$in": orphaned_revenue_ids}})
        db.treasury_payouts.delete_many({"revenue_id": {"$in": orphaned_revenue_ids}})


def normalize_stakeholder_flow_payouts(db):
    """Reclassify stakeholder splits on company expenses as contributions, not earnings."""
    expense_rev_ids = [
        doc["id"]
        for doc in db.treasury_revenue.find({"amount": {"$lt": 0}}, {"id": 1, "_id": 0})
    ]
    if expense_rev_ids:
        db.treasury_payouts.update_many(
            {
                "revenue_id": {"$in": expense_rev_ids},
                "payout_type": "Stakeholder",
            },
            {"$set": {"payout_type": "Stakeholder Contribution", "status": "Received"}},
        )


def _format_pct(value):
    rounded = round(float(value), 2)
    return int(rounded) if rounded == int(rounded) else rounded


def format_stakeholder_audit_details(old_doc, new_data):
    """Build human-readable audit text for stakeholder create/update."""
    name = new_data.get("name") or old_doc.get("name", "Unknown")
    parts = [f"Owner: {name}"]

    if old_doc:
        old_name = old_doc.get("name", "")
        new_name = new_data.get("name", "")
        if old_name != new_name:
            parts.append(f"name changed '{old_name}' → '{new_name}'")

        old_pct = float(old_doc.get("payout_percentage", old_doc.get("equity_percentage", 0)))
        new_pct = float(new_data.get("payout_percentage", 0))
        if old_pct != new_pct:
            parts.append(f"equity % changed {_format_pct(old_pct)}% → {_format_pct(new_pct)}%")

        old_active = bool(old_doc.get("is_active", True))
        new_active = bool(new_data.get("is_active", True))
        if old_active != new_active:
            parts.append(f"status changed to {'Active' if new_active else 'Inactive'}")

        old_details = (old_doc.get("payment_details") or "").strip()
        new_details = (new_data.get("payment_details") or "").strip()
        if old_details != new_details:
            parts.append("payment/bank details updated")
    else:
        pct = float(new_data.get("payout_percentage", 0))
        parts.append(f"equity {_format_pct(pct)}%")
        parts.append("Active" if new_data.get("is_active", True) else "Inactive")
        if (new_data.get("payment_details") or "").strip():
            parts.append("payment details provided")

    if len(parts) == 1:
        parts.append("no field changes detected")
    return "; ".join(parts)


import threading

def _perform_log_activity(module_name, entity_name, record_id, action_type, old_data, new_data, reference_number, source_screen, user_id, user_name):
    try:
        fields_changed = []
        old_values = {}
        new_values = {}
        
        def sanitize_val(v):
            if isinstance(v, (datetime, date)):
                return v.isoformat()
            if isinstance(v, Decimal):
                return float(v)
            if isinstance(v, bytes):
                return v.decode("utf-8", errors="ignore")
            return v

        if action_type == "UPDATE":
            if not old_data:
                old_data = {}
            if not new_data:
                new_data = {}
            
            all_keys = set(old_data.keys()).union(new_data.keys())
            ignored_keys = {"_id", "updated_at", "modified_at", "created_at", "modified_by_id", "modified_by_name", "created_by_id", "created_by_name"}
            
            for key in all_keys:
                if key in ignored_keys:
                    continue
                old_val = old_data.get(key)
                new_val = new_data.get(key)
                
                if old_val != new_val:
                    fields_changed.append(key)
                    if key in old_data:
                        old_values[key] = sanitize_val(old_val)
                    if key in new_data:
                        new_values[key] = sanitize_val(new_val)
                        
            if not fields_changed:
                return
        elif action_type == "CREATE":
            if new_data:
                ignored_keys = {"_id", "updated_at", "modified_at", "created_at", "modified_by_id", "modified_by_name", "created_by_id", "created_by_name"}
                for key, val in new_data.items():
                    if key not in ignored_keys:
                        new_values[key] = sanitize_val(val)
                fields_changed = list(new_values.keys())
        elif action_type == "DELETE":
            if old_data:
                ignored_keys = {"_id", "updated_at", "modified_at", "created_at", "modified_by_id", "modified_by_name", "created_by_id", "created_by_name"}
                for key, val in old_data.items():
                    if key not in ignored_keys:
                        old_values[key] = sanitize_val(val)
                fields_changed = list(old_values.keys())

        db = get_db()
        log_id = get_next_sequence_value("activity_logs")
        db.activity_logs.insert_one({
            "id": log_id,
            "module_name": module_name,
            "entity_name": entity_name,
            "record_id": record_id,
            "action_type": action_type,
            "fields_changed": fields_changed,
            "old_values": old_values,
            "new_values": new_values,
            "user_id": user_id,
            "user_name": user_name,
            "timestamp": datetime.now(),
            "reference_number": reference_number,
            "source_screen": source_screen
        })
    except Exception as e:
        print(f"ASYNC LOGGING ERROR: {e}")

def log_activity_async(module_name, entity_name, record_id, action_type, old_data=None, new_data=None, reference_number=None):
    try:
        source_screen = request.path if request else None
        actor = get_current_user()
        user_id = actor["id"] if actor else None
        user_name = actor.get("full_name", "System") if actor else "System"
        
        old_data_copy = dict(old_data) if old_data else None
        new_data_copy = dict(new_data) if new_data else None
        
        thread = threading.Thread(
            target=_perform_log_activity,
            args=(module_name, entity_name, record_id, action_type, old_data_copy, new_data_copy, reference_number, source_screen, user_id, user_name),
            daemon=True
        )
        thread.start()
    except Exception as e:
        print(f"FAILED TO INITIATE ASYNC LOGGING: {e}")



def dashboard_payload():
    db = get_db()
    
    metrics = {
        "customers": db.customers.count_documents({}),
        "open_opportunities": db.opportunities.count_documents({"stage": {"$nin": ["DA Signed", "Lost to competitor", "Rejected by SC", "Lost"]}}),
        "pipeline_values": list(db.opportunities.aggregate([
            {"$match": {"stage": {"$nin": ["DA Signed", "Lost to competitor", "Rejected by SC", "Lost"]}}},
            {"$group": {"_id": "$currency", "total": {"$sum": "$value"}}},
            {"$project": {"_id": 0, "currency": "$_id", "total": 1}}
        ])),
        "active_projects": db.projects.count_documents({"status": {"$in": ["Planning", "In Progress", "Blocked"]}}),
    }
    
    recent_opportunities = list(db.opportunities.aggregate([
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"company_name": "$customer.company_name"}},
        {"$project": {"_id": 0, "customer": 0}},
        {"$sort": {"updated_at": -1}},
        {"$limit": 6}
    ]))
    
    upcoming_projects = list(db.projects.aggregate([
        {"$match": {"status": {"$ne": "Delivered"}}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"company_name": "$customer.company_name"}},
        {"$project": {"_id": 0, "customer": 0}},
        {"$sort": {"delivery_timeline": 1}},
        {"$limit": 6}
    ]))
    
    opportunities_by_stage = list(db.opportunities.aggregate([
        {"$group": {"_id": "$stage", "count": {"$sum": 1}}},
        {"$project": {"_id": 0, "stage": "$_id", "count": 1}}
    ]))
    
    pipeline_value_by_stage = list(db.opportunities.aggregate([
        {"$group": {"_id": "$stage", "total": {"$sum": "$value"}}},
        {"$project": {"_id": 0, "stage": "$_id", "total": 1}}
    ]))
    
    return {
        "metrics": metrics,
        "recent_opportunities": recent_opportunities,
        "upcoming_projects": upcoming_projects,
        "opportunities_by_stage": opportunities_by_stage,
        "pipeline_value_by_stage": pipeline_value_by_stage,
        "currency_symbols": CURRENCY_SYMBOLS,
    }


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(json_ready(dashboard_payload()))


@app.route("/api/options")
def api_options():
    db = get_db()
    ensure_default_accounts(db)
    customers_list = list(db.customers.find({}, {"_id": 0, "id": 1, "company_name": 1}).sort("company_name", 1))
    
    opportunities_list = list(db.opportunities.aggregate([
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$project": {"_id": 0, "id": 1, "title": 1, "customer_id": 1, "stage": 1, "company_name": "$customer.company_name"}},
        {"$sort": {"company_name": 1, "title": 1}}
    ]))
    
    accounts = list(db.accounts.find({}, {"_id": 0}).sort("name", 1))
    vendors = list(db.vendors.find({}, {"_id": 0, "id": 1, "name": 1}).sort("name", 1))
    projects_list = list(db.projects.find({}, {"_id": 0, "id": 1, "project_name": 1, "customer_id": 1}).sort("project_name", 1))
    
    # Dynamically fetch picklists from custom_fields
    import json
    
    # Customers Status
    customer_obj = db.custom_objects.find_one({"api_name": "customers"})
    customer_status_field = db.custom_fields.find_one({"object_id": customer_obj["id"], "api_name": "status"}) if customer_obj else None
    customer_statuses = json.loads(customer_status_field["picklist_options"]) if customer_status_field and customer_status_field.get("picklist_options") else CUSTOMER_STATUSES
    
    # Opportunities Stage
    opp_obj = db.custom_objects.find_one({"api_name": "opportunities"})
    opp_stage_field = db.custom_fields.find_one({"object_id": opp_obj["id"], "api_name": "stage"}) if opp_obj else None
    opportunity_stages = json.loads(opp_stage_field["picklist_options"]) if opp_stage_field and opp_stage_field.get("picklist_options") else OPPORTUNITY_STAGES
    
    # Projects Status
    proj_obj = db.custom_objects.find_one({"api_name": "projects"})
    proj_status_field = db.custom_fields.find_one({"object_id": proj_obj["id"], "api_name": "status"}) if proj_obj else None
    project_statuses = json.loads(proj_status_field["picklist_options"]) if proj_status_field and proj_status_field.get("picklist_options") else PROJECT_STATUSES
    
    return jsonify(
        json_ready(
            {
                "customer_statuses": customer_statuses,
                "opportunity_stages": opportunity_stages,
                "project_statuses": project_statuses,
                "currencies": CURRENCIES,
                "customers": customers_list,
                "opportunities": opportunities_list,
                "accounts": accounts,
                "vendors": vendors,
                "projects": projects_list,
                "payment_terms": active_master_option_names(db, "payment-terms"),
                "payment_modes": active_master_option_names(db, "payment-modes"),
                "bank_accounts": list(
                    db.bank_accounts.find({"is_active": {"$ne": 0}}, {"_id": 0}).sort("label", 1)
                ),
            }
        )
    )


ACCOUNT_TYPES = {"Asset", "Liability", "Equity", "Revenue", "Expense"}


def bool_flag(value):
    return 1 if value in (True, 1, "1", "true", "True", "on", "yes", "Yes") else 0


def ensure_master_options(db, config):
    collection = db[config["collection"]]
    for name in config["defaults"]:
        if not collection.find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}):
            option_id = get_next_sequence_value(config["counter"])
            collection.insert_one({
                "id": option_id,
                "name": name,
                "is_active": 1,
                "is_default": 1,
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
            })


def active_master_option_names(db, key):
    config = MASTER_OPTION_CONFIG[key]
    ensure_master_options(db, config)
    return [
        item["name"]
        for item in db[config["collection"]].find({"is_active": {"$ne": 0}}, {"_id": 0, "name": 1}).sort("name", 1)
    ]


def validate_profile_master_fields(db, data, include_supplier_fields=False):
    registration_type = data.get("registration_type")
    if registration_type and registration_type not in REGISTRATION_TYPES:
        return "Registration Type must be Registered or Not Registered."

    if include_supplier_fields:
        supplier_category = data.get("supplier_category")
        if supplier_category and supplier_category not in SUPPLIER_CATEGORIES:
            return "Supplier Category must be MSME or Non-MSME."

    payment_terms = data.get("payment_terms")
    if payment_terms and payment_terms not in active_master_option_names(db, "payment-terms"):
        return "Select an active Payment Term from settings."

    payment_mode = data.get("payment_mode")
    if payment_mode and payment_mode not in active_master_option_names(db, "payment-modes"):
        return "Select an active Payment Mode from settings."

    return None


def parse_float(value, default=0.0):
    try:
        return float(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        return default


def claim_gst_breakdown(base_amount, gst_percent=0.0, gst_amount=0.0, total_amount=0.0):
    base = parse_float(base_amount)
    percent = parse_float(gst_percent)
    stored_gst = parse_float(gst_amount)
    total = parse_float(total_amount)
    if base <= 0:
        return 0.0, 0.0, percent, 0.0
    if percent > 0:
        cgst = round(base * (percent / 100.0), 2)
        return round(base, 2), cgst, percent, total or round(base + cgst, 2)
    if stored_gst > 0:
        percent = round((stored_gst / base) * 100.0, 2)
        return round(base, 2), round(stored_gst, 2), percent, total or round(base + stored_gst, 2)
    return round(base, 2), 0.0, 0.0, total or round(base, 2)


def safe_int(value):
    if value in (None, ""):
        return None
    return int(value)


def create_finance_transaction(db, payload, actor=None):
    transaction_id = get_next_sequence_value("transactions")
    amount = parse_float(payload.get("amount"))
    cgst_amount = parse_float(payload.get("cgst_amount"))
    igst_amount = parse_float(payload.get("igst_amount"))
    tds_amount = parse_float(payload.get("tds_amount"))
    total_amount = parse_float(payload.get("total_amount"), amount + cgst_amount + igst_amount - tds_amount)
    date_val = payload.get("transaction_date") or payload.get("date") or datetime.now().strftime("%Y-%m-%d")
    actor_id = actor["id"] if actor else None
    actor_name = actor.get("full_name", "Unknown") if actor else "System"
    doc = {
        "id": transaction_id,
        "account_id": safe_int(payload.get("account_id")),
        "customer_id": safe_int(payload.get("customer_id")),
        "vendor_id": safe_int(payload.get("vendor_id")),
        "project_id": safe_int(payload.get("project_id")),
        "invoice_id": safe_int(payload.get("invoice_id")),
        "invoice_number": payload.get("invoice_number"),
        "loan_account_id": safe_int(payload.get("loan_account_id")),
        "loan_schedule_id": safe_int(payload.get("loan_schedule_id")),
        "expense_claim_id": safe_int(payload.get("expense_claim_id")),
        "attachments": payload.get("attachments") or [],
        "transaction_date": date_val,
        "date": date_val,
        "description": payload.get("description"),
        "type": payload.get("type", "Income"),
        "amount": amount,
        "currency": payload.get("currency", "INR"),
        "reference": payload.get("reference"),
        "category": payload.get("category"),
        "status": payload.get("status", "Completed"),
        "cgst_percent": parse_float(payload.get("cgst_percent")),
        "cgst_amount": cgst_amount,
        "igst_percent": parse_float(payload.get("igst_percent")),
        "igst_amount": igst_amount,
        "tds_percent": parse_float(payload.get("tds_percent")),
        "tds_amount": tds_amount,
        "total_amount": total_amount,
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
        "created_by_id": actor_id,
        "created_by_name": actor_name,
        "modified_by_id": actor_id,
        "modified_by_name": actor_name,
    }
    db.transactions.insert_one(doc)
    log_activity_async("Finance", "Accounting Entry", transaction_id, "CREATE", new_data=doc, reference_number=doc.get("reference"))
    return doc


def sync_transaction_to_treasury_revenue(db, transaction_doc):
    existing = db.treasury_revenue.find_one({"transaction_id": transaction_doc["id"]})
    if existing and existing.get("is_settled"):
        return existing
    amount = parse_float(transaction_doc.get("total_amount") or transaction_doc.get("amount"))
    if transaction_doc.get("type") == "Expense":
        amount = -abs(amount)
        revenue_type = transaction_doc.get("category") or "Company Expense"
        reserve_percentage = 100.0
    else:
        amount = abs(amount)
        revenue_type = transaction_doc.get("category") or "Loan Disbursement"
        reserve_percentage = 100.0
    reserve_amount = amount * (reserve_percentage / 100.0)
    stakeholder_total = 0.0
    entry_date = transaction_doc.get("transaction_date") or datetime.now().strftime("%Y-%m-%d")
    payload = {
        "transaction_id": transaction_doc["id"],
        "project_id": transaction_doc.get("project_id"),
        "entry_date": entry_date,
        "date": datetime.strptime(entry_date, "%Y-%m-%d") if isinstance(entry_date, str) else entry_date,
        "revenue_type": revenue_type,
        "amount": amount,
        "reserve_percentage": reserve_percentage,
        "reserve_amount": reserve_amount,
        "channel_partner_id": None,
        "partner_commission": 0.0,
        "stakeholder_total": stakeholder_total,
        "description": transaction_doc.get("description") or f"Auto-flow from Transaction Ledger #{transaction_doc['id']}",
        "is_settled": False,
        "updated_at": datetime.now(),
    }
    if existing:
        db.treasury_revenue.update_one({"id": existing["id"]}, {"$set": payload})
        updated = db.treasury_revenue.find_one({"id": existing["id"]})
        if amount < 0:
            create_or_update_payable_from_revenue(db, updated)
        return updated
    rev_id = get_next_sequence_value("treasury_revenue")
    payload.update({
        "id": rev_id,
        "revenue_id": f"REV-{rev_id}",
        "created_at": datetime.now(),
    })
    db.treasury_revenue.insert_one(payload)
    if amount < 0:
        create_or_update_payable_from_revenue(db, payload)
    return payload


def claim_summary(doc):
    total = parse_float(doc.get("total_claim_amount"))
    amount = parse_float(doc.get("amount"))
    gst_amount = parse_float(doc.get("gst_amount"))
    gst_percent = parse_float(doc.get("gst_percent"))
    if not gst_percent and amount > 0 and gst_amount > 0:
        gst_percent = round((gst_amount / amount) * 100, 2)
    return {
        **doc,
        "total_claim_amount": total,
        "amount": amount,
        "gst_amount": gst_amount,
        "gst_percent": gst_percent,
    }


def claim_has_active_posted_transaction(db, claim):
    tx_id = claim.get("posted_transaction_id")
    if not tx_id:
        return False
    return bool(db.transactions.find_one({"id": tx_id, "status": {"$ne": "Reversed"}}))


def release_claim_posting_if_reversed(db, tx):
    if not tx or not tx.get("expense_claim_id"):
        return
    db.expense_claims.update_one(
        {"id": tx.get("expense_claim_id"), "posted_transaction_id": tx.get("id")},
        {
            "$set": {
                "status": "Approved",
                "updated_at": datetime.now(),
            },
            "$unset": {
                "posted_transaction_id": "",
                "posted_at": "",
                "posted_by": "",
            },
        },
    )


def reverse_payables_for_revenue(db, revenue_doc, transaction_id=None):
    if not revenue_doc:
        return
    db.payables.update_many(
        {"source_module": "Revenue Log", "source_id": revenue_doc.get("id"), "status": {"$ne": "Paid"}},
        {
            "$set": {
                "status": "Reversed",
                "payment_status": "Reversed",
                "outstanding_amount": 0.0,
                "reversed_at": datetime.now(),
                "reversed_transaction_id": transaction_id,
                "updated_at": datetime.now(),
            }
        },
    )


def active_claim_approvers(db):
    return list(
        db.treasury_stakeholders.aggregate([
            {"$match": {
                "is_active": {"$ne": False},
                "linked_user_id": {"$nin": [None, ""]},
            }},
            {"$lookup": {"from": "app_users", "localField": "linked_user_id", "foreignField": "id", "as": "linked_user"}},
            {"$unwind": "$linked_user"},
            {"$match": {"linked_user.is_active": {"$ne": 0}}},
            {"$addFields": {"approval_sequence": {"$ifNull": ["$approval_sequence", 999]}}},
            {"$sort": {"approval_sequence": 1, "id": 1}},
            {"$project": {"_id": 0, "linked_user": 0}},
        ])
    )


def claim_pending_status(sequence):
    return "Pending Stakeholder Approval"


def approval_display_name(step):
    return (
        step.get("linked_user_name")
        or step.get("action_by_name")
        or step.get("stakeholder_name")
        or step.get("email")
        or "Assigned Approver"
    )


def pending_approval_steps(db, collection_name, record_field, record_id, sequence=None):
    query = {record_field: record_id, "status": "Pending"}
    if sequence is not None:
        query["approval_sequence"] = sequence
    return list(db[collection_name].aggregate([
        {"$match": query},
        {"$lookup": {"from": "app_users", "localField": "linked_user_id", "foreignField": "id", "as": "linked_user"}},
        {"$unwind": {"path": "$linked_user", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"linked_user_name": "$linked_user.full_name"}},
        {"$project": {"linked_user": 0, "_id": 0}},
        {"$sort": {"approval_sequence": 1, "id": 1}},
    ]))


def pending_approval_status(db, collection_name, record_field, record_id, sequence=None):
    steps = pending_approval_steps(db, collection_name, record_field, record_id, sequence)
    names = [approval_display_name(step) for step in steps]
    if names:
        return f"Pending Approval from {', '.join(names)}"
    return claim_pending_status(sequence)


def attach_approval_user_names(db, steps):
    user_ids = [step.get("linked_user_id") for step in steps if step.get("linked_user_id")]
    users = {
        user["id"]: user
        for user in db.app_users.find({"id": {"$in": user_ids}}, {"_id": 0, "id": 1, "full_name": 1, "email": 1})
    } if user_ids else {}
    for step in steps:
        user = users.get(step.get("linked_user_id"))
        if user:
            step["linked_user_name"] = user.get("full_name")
            step["approver_name"] = user.get("full_name") or step.get("stakeholder_name")
        else:
            step["approver_name"] = approval_display_name(step)
    return steps


def attach_pending_approval_display(db, doc, collection_name, record_field):
    if not doc:
        return doc
    if str(doc.get("status", "")).startswith("Pending Approval") or doc.get("approval_required"):
        sequence = doc.get("current_approval_sequence")
        steps = pending_approval_steps(db, collection_name, record_field, doc.get("id"), sequence)
        names = [approval_display_name(step) for step in steps]
        if names:
            doc["current_pending_approvers"] = names
            doc["status"] = f"Pending Approval from {', '.join(names)}"
    return doc


def create_system_notification(db, user_id, title, message, link=None):
    if not user_id:
        return
    notification_id = get_next_sequence_value("notifications")
    db.notifications.insert_one({
        "id": notification_id,
        "user_id": user_id,
        "title": title,
        "message": message,
        "link": link,
        "is_read": False,
        "created_at": datetime.now(),
    })


def company_fund_available(db):
    settled_revenue_ids = get_settled_revenue_ids(db)
    reserve_balance_match = reserve_balance_payout_clause(settled_revenue_ids)
    inflow_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Reserve Fund", **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]))
    outflow_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": {"$in": ["Reserve Expense", "Stakeholder Payout", "Channel Partner Payout"]}, **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]))
    inflow = inflow_doc[0]["total"] if inflow_doc else 0.0
    outflow = outflow_doc[0]["total"] if outflow_doc else 0.0
    return inflow - outflow


def payout_recipient_payload(db, data, existing=None):
    existing = existing or {}
    recipient_type = data.get("recipient_type") or existing.get("recipient_type") or "Stakeholder"
    if recipient_type not in PAYOUT_RECIPIENT_TYPES:
        return None, "Select a valid payout recipient type."

    if recipient_type == "Channel Partner":
        partner_id = safe_int(data.get("partner_id", existing.get("partner_id")))
        partner = db.treasury_partners.find_one({"id": partner_id, "is_active": {"$ne": False}})
        if not partner:
            return None, "Select an active channel partner."
        name = partner.get("name") or partner.get("partner_name")
        return {
            "recipient_type": "Channel Partner",
            "recipient_id": partner_id,
            "recipient_name": name,
            "partner_id": partner_id,
            "partner_name": name,
            "stakeholder_id": None,
            "stakeholder_name": None,
            "stakeholder_account": data.get("stakeholder_account", existing.get("stakeholder_account")),
        }, None

    stakeholder_id = safe_int(data.get("stakeholder_id", existing.get("stakeholder_id")))
    stakeholder = db.treasury_stakeholders.find_one({"id": stakeholder_id, "is_active": {"$ne": False}})
    if not stakeholder:
        return None, "Select an active stakeholder."
    name = stakeholder.get("name")
    return {
        "recipient_type": "Stakeholder",
        "recipient_id": stakeholder_id,
        "recipient_name": name,
        "stakeholder_id": stakeholder_id,
        "stakeholder_name": name,
        "stakeholder_account": data.get("stakeholder_account", existing.get("stakeholder_account")) or stakeholder.get("payment_details"),
        "partner_id": None,
        "partner_name": None,
    }, None


def normalize_payout_recipient(doc):
    if not doc:
        return doc
    doc.setdefault("recipient_type", "Stakeholder")
    if doc.get("recipient_type") == "Channel Partner":
        doc["recipient_name"] = doc.get("recipient_name") or doc.get("partner_name")
        doc["recipient_id"] = doc.get("recipient_id") or doc.get("partner_id")
    else:
        doc["recipient_name"] = doc.get("recipient_name") or doc.get("stakeholder_name")
        doc["recipient_id"] = doc.get("recipient_id") or doc.get("stakeholder_id")
    return doc


def can_manage_payout_approvals(user, db):
    if not user:
        return False
    role = db.roles.find_one({"id": user.get("role_id")}, {"_id": 0, "name": 1}) if user.get("role_id") else None
    is_admin = role and role.get("name") in ["Admin", "System Administrator"]
    return bool(is_admin or user.get("has_treasury_access"))


def create_or_update_payable_from_revenue(db, revenue_doc):
    amount = abs(parse_float(revenue_doc.get("amount")))
    if amount <= 0:
        return None
    existing = db.payables.find_one({"source_module": "Revenue Log", "source_id": revenue_doc.get("id")})
    if existing and existing.get("status") == "Paid":
        return existing
    paid_amount = parse_float((existing or {}).get("paid_amount"))
    outstanding = max(0.0, amount - paid_amount)
    status = "Paid" if outstanding <= 0.01 else ("Partially Paid" if paid_amount > 0 else "Pending")
    payload = {
        "source_module": "Revenue Log",
        "source_id": revenue_doc.get("id"),
        "source_reference": revenue_doc.get("revenue_id") or f"REV-{revenue_doc.get('id')}",
        "transaction_id": revenue_doc.get("transaction_id"),
        "party_name": revenue_doc.get("vendor_name") or revenue_doc.get("employee_name") or revenue_doc.get("stakeholder_name") or revenue_doc.get("description") or "Company Expense",
        "transaction_date": revenue_doc.get("entry_date") or revenue_doc.get("date") or datetime.now().strftime("%Y-%m-%d"),
        "original_amount": amount,
        "paid_amount": paid_amount,
        "outstanding_amount": outstanding,
        "payment_status": status,
        "status": status,
        "due_date": revenue_doc.get("entry_date"),
        "remarks": revenue_doc.get("description"),
        "updated_at": datetime.now(),
    }
    if existing:
        db.payables.update_one({"id": existing["id"]}, {"$set": payload})
        return db.payables.find_one({"id": existing["id"]})
    payable_id = get_next_sequence_value("payables")
    payload.update({
        "id": payable_id,
        "payable_number": f"PAY-{payable_id:05d}",
        "created_at": datetime.now(),
    })
    db.payables.insert_one(payload)
    return payload


def payout_payable_source_module(payout):
    return "Channel Partner Payout" if payout.get("recipient_type") == "Channel Partner" else "Stakeholder Payout"


def create_or_update_payable_from_payout(db, payout):
    if not payout or payout.get("status") not in {"Approved", "Pending Payment", "Partially Paid", "Paid"}:
        return None
    amount = parse_float(payout.get("amount"))
    if amount <= 0:
        return None
    source_module = payout_payable_source_module(payout)
    existing = db.payables.find_one({"source_module": source_module, "source_id": payout.get("id")})
    if existing and existing.get("status") == "Paid":
        return existing
    paid_amount = parse_float((existing or {}).get("paid_amount"), payout.get("paid_amount"))
    outstanding = max(0.0, amount - paid_amount)
    status = "Paid" if outstanding <= 0.01 else ("Partially Paid" if paid_amount > 0 else "Pending")
    payload = {
        "source_module": source_module,
        "source_id": payout.get("id"),
        "source_reference": payout.get("payout_number") or f"SP-{payout.get('id')}",
        "party_name": payout.get("recipient_name") or payout.get("partner_name") or payout.get("stakeholder_name") or "Payout Recipient",
        "transaction_date": payout.get("payout_date") or datetime.now().strftime("%Y-%m-%d"),
        "original_amount": amount,
        "paid_amount": paid_amount,
        "outstanding_amount": outstanding,
        "payment_status": status,
        "status": status,
        "due_date": payout.get("payout_date"),
        "remarks": payout.get("remarks") or payout.get("payout_type"),
        "updated_at": datetime.now(),
    }
    if existing:
        db.payables.update_one({"id": existing["id"]}, {"$set": payload})
        db.stakeholder_payout_receipts.update_one(
            {"id": payout.get("id")},
            {"$set": {"payable_id": existing["id"], "status": status if status != "Pending" else "Pending Payment", "updated_at": datetime.now()}},
        )
        return db.payables.find_one({"id": existing["id"]})
    payable_id = get_next_sequence_value("payables")
    payload.update({
        "id": payable_id,
        "payable_number": f"PAY-{payable_id:05d}",
        "created_at": datetime.now(),
    })
    db.payables.insert_one(payload)
    db.stakeholder_payout_receipts.update_one(
        {"id": payout.get("id")},
        {"$set": {"payable_id": payable_id, "status": "Pending Payment", "updated_at": datetime.now()}},
    )
    return payload


def sync_negative_revenue_payables(db):
    for revenue_doc in db.treasury_revenue.find({"amount": {"$lt": 0}}):
        create_or_update_payable_from_revenue(db, revenue_doc)


def sync_reversed_transaction_payables(db):
    reversed_tx_ids = [
        tx["id"]
        for tx in db.transactions.find({"status": "Reversed"}, {"_id": 0, "id": 1})
    ]
    if not reversed_tx_ids:
        return
    reversed_revenues = list(
        db.treasury_revenue.find({"transaction_id": {"$in": reversed_tx_ids}}, {"_id": 0, "id": 1, "transaction_id": 1})
    )
    for revenue_doc in reversed_revenues:
        reverse_payables_for_revenue(db, revenue_doc, revenue_doc.get("transaction_id"))
    orphaned_payables = db.payables.find({
        "source_module": "Revenue Log",
        "status": {"$nin": ["Paid", "Reversed"]},
        "source_reference": {"$regex": r"^REV-"},
    }, {"_id": 0, "id": 1, "source_id": 1})
    for payable in orphaned_payables:
        source_id = payable.get("source_id")
        if source_id and not db.treasury_revenue.find_one({"id": source_id}):
            db.payables.update_one(
                {"id": payable["id"]},
                {"$set": {
                    "status": "Reversed",
                    "payment_status": "Reversed",
                    "outstanding_amount": 0.0,
                    "updated_at": datetime.now(),
                }},
            )


def sync_approved_payout_payables(db):
    for payout in db.stakeholder_payout_receipts.find({"status": {"$in": ["Approved", "Pending Payment", "Partially Paid", "Paid"]}}):
        create_or_update_payable_from_payout(db, payout)


def initialize_claim_approval_workflow(db, claim_id, actor=None):
    claim = db.expense_claims.find_one({"id": claim_id})
    if not claim:
        return None
    approvers = active_claim_approvers(db)
    if not approvers:
        status = "Approved"
        db.expense_claims.update_one(
            {"id": claim_id},
            {"$set": {
                "status": status,
                "approval_required": False,
                "approval_completed": True,
                "submitted_at": datetime.now(),
                "submitted_by_id": actor["id"] if actor else claim.get("created_by_id"),
                "updated_at": datetime.now(),
            }},
        )
        return status

    db.claim_approvals.delete_many({"claim_id": claim_id})
    now = datetime.now()
    steps = []
    for approver in approvers:
        sequence = int(approver.get("approval_sequence") or 999)
        steps.append({
            "id": get_next_sequence_value("claim_approvals"),
            "claim_id": claim_id,
            "stakeholder_id": approver.get("id"),
            "stakeholder_name": approver.get("name"),
            "email": approver.get("email"),
            "linked_user_id": approver.get("linked_user_id"),
            "approval_sequence": sequence,
            "status": "Pending" if sequence == int(approvers[0].get("approval_sequence") or 999) else "Waiting",
            "remarks": "",
            "created_at": now,
        })
    if steps:
        db.claim_approvals.insert_many(steps)
    first_sequence = steps[0]["approval_sequence"]
    status = pending_approval_status(db, "claim_approvals", "claim_id", claim_id, first_sequence)
    db.expense_claims.update_one(
        {"id": claim_id},
        {"$set": {
            "status": status,
            "approval_required": True,
            "approval_completed": False,
            "current_approval_sequence": first_sequence,
            "submitted_at": now,
            "submitted_by_id": actor["id"] if actor else claim.get("created_by_id"),
            "updated_at": now,
        }},
    )
    for step in steps:
        if step["approval_sequence"] == first_sequence:
            create_system_notification(
                db,
                step.get("linked_user_id"),
                "Expense claim approval pending",
                f"{claim.get('claim_number')} is waiting for your approval.",
                "/claims/approvals",
            )
    return status


def initialize_stakeholder_payout_approval_workflow(db, payout_id, actor=None):
    payout = db.stakeholder_payout_receipts.find_one({"id": payout_id})
    if not payout:
        return None
    excluded_stakeholder_id = payout.get("stakeholder_id") if payout.get("recipient_type", "Stakeholder") == "Stakeholder" else None
    approvers = [
        approver for approver in active_claim_approvers(db)
        if approver.get("id") != excluded_stakeholder_id
    ]
    if not approvers:
        status = "Approved"
        db.stakeholder_payout_receipts.update_one(
            {"id": payout_id},
            {"$set": {
                "status": status,
                "approval_required": False,
                "approval_completed": True,
                "submitted_at": datetime.now(),
                "submitted_by_id": actor["id"] if actor else payout.get("created_by_id"),
                "updated_at": datetime.now(),
            }},
        )
        return status

    db.stakeholder_payout_approvals.delete_many({"payout_id": payout_id})
    now = datetime.now()
    first_sequence = int(approvers[0].get("approval_sequence") or 999)
    steps = []
    for approver in approvers:
        sequence = int(approver.get("approval_sequence") or 999)
        steps.append({
            "id": get_next_sequence_value("stakeholder_payout_approvals"),
            "payout_id": payout_id,
            "stakeholder_id": approver.get("id"),
            "stakeholder_name": approver.get("name"),
            "email": approver.get("email"),
            "linked_user_id": approver.get("linked_user_id"),
            "approval_sequence": sequence,
            "status": "Pending" if sequence == first_sequence else "Waiting",
            "remarks": "",
            "created_at": now,
        })
    if steps:
        db.stakeholder_payout_approvals.insert_many(steps)
    status = pending_approval_status(db, "stakeholder_payout_approvals", "payout_id", payout_id, first_sequence)
    db.stakeholder_payout_receipts.update_one(
        {"id": payout_id},
        {"$set": {
            "status": status,
            "approval_required": True,
            "approval_completed": False,
            "current_approval_sequence": first_sequence,
            "submitted_at": now,
            "submitted_by_id": actor["id"] if actor else payout.get("created_by_id"),
            "updated_at": now,
        }},
    )
    for step in steps:
        if step["approval_sequence"] == first_sequence:
            create_system_notification(
                db,
                step.get("linked_user_id"),
                "Payout approval pending",
                f"{payout.get('payout_number')} is waiting for your approval.",
                "/treasury/stakeholder-payouts/approvals",
            )
    return status


def loan_totals(db, loan_id):
    disbursed = sum(parse_float(d.get("amount")) for d in db.loan_disbursements.find({"loan_id": loan_id, "status": "Posted"}))
    principal_repaid = 0.0
    for schedule in db.loan_repayment_schedules.find({"loan_id": loan_id, "status": {"$in": ["Paid", "Partially Paid"]}}):
        paid_amount = parse_float(schedule.get("paid_amount"))
        total_due = parse_float(schedule.get("total_amount"))
        principal = parse_float(schedule.get("principal_amount"))
        if total_due > 0 and paid_amount > 0:
            principal_repaid += min(principal, principal * min(paid_amount / total_due, 1))
    return {
        "total_disbursed_amount": disbursed,
        "total_principal_repaid": principal_repaid,
        "outstanding_balance": max(0.0, disbursed - principal_repaid),
    }


def default_account_visibility(account_type):
    return {
        "show_in_income": 1 if account_type == "Revenue" else 0,
        "show_in_expense": 1 if account_type == "Expense" else 0,
    }


def normalize_account_payload(data, existing=None):
    gl_code = (data.get("gl_code") or "").strip()
    name = (data.get("name") or "").strip()
    account_type = (data.get("type") or (existing or {}).get("type") or "Revenue").strip()
    defaults = default_account_visibility(account_type)

    if not gl_code:
        return None, "GL code is required."
    if not name:
        return None, "Name is required."
    if account_type not in ACCOUNT_TYPES:
        return None, "Invalid account type."

    return {
        "gl_code": gl_code,
        "name": name,
        "type": account_type,
        "is_active": bool_flag(data.get("is_active", (existing or {}).get("is_active", 1))),
        "show_in_income": bool_flag(data.get("show_in_income", (existing or {}).get("show_in_income", defaults["show_in_income"]))),
        "show_in_expense": bool_flag(data.get("show_in_expense", (existing or {}).get("show_in_expense", defaults["show_in_expense"]))),
    }, None


def account_available_for_transaction(account, transaction_type):
    if not account or not account.get("is_active", 1):
        return False
    if transaction_type == "Income":
        return bool(account.get("show_in_income", 1 if account.get("type") == "Revenue" else 0))
    if transaction_type == "Expense":
        return bool(account.get("show_in_expense", 1 if account.get("type") == "Expense" else 0))
    return False


INVOICE_RECEIPT_STATUSES = ["Approved", "Partially Paid", "Paid"]
APPROVED_INVOICE_STATUSES = {"Approved", "Partially Paid", "Paid"}
POST_APPROVAL_INVOICE_STATUSES = {"Approved", "Partially Paid", "Paid", "Cancelled"}


def invoice_receipt_summary(invoice):
    paid = float(invoice.get("amount_paid") or 0)
    total = float(invoice.get("total_amount") or 0)
    balance = max(0, total - paid)
    return {
        "id": invoice.get("id"),
        "invoice_number": invoice.get("invoice_number"),
        "customer_id": invoice.get("customer_id"),
        "project_id": invoice.get("project_id"),
        "account_id": invoice.get("account_id"),
        "invoice_date": invoice.get("issue_date"),
        "due_date": invoice.get("due_date"),
        "currency": invoice.get("currency"),
        "status": invoice.get("status"),
        "total_amount": total,
        "amount_paid": paid,
        "balance_due": balance,
    }


def normalize_invoice_amount_paid(status, amount_paid, total_amount):
    total = max(0.0, float(total_amount or 0))
    if status == "Paid":
        return total
    if status == "Partially Paid":
        paid = float(amount_paid or 0)
        return min(max(0.0, paid), total)
    return 0.0


def invoice_core_values(invoice):
    return {
        "invoice_number": invoice.get("invoice_number"),
        "customer_id": int(invoice["customer_id"]) if invoice.get("customer_id") else None,
        "project_id": int(invoice["project_id"]) if invoice.get("project_id") else None,
        "account_id": int(invoice["account_id"]) if invoice.get("account_id") else None,
        "issue_date": invoice.get("invoice_date") or invoice.get("issue_date"),
        "due_date": invoice.get("due_date"),
        "subtotal": float(invoice.get("subtotal") or 0),
        "tax_rate": float(invoice.get("tax_rate") or 0),
        "tax_amount": float(invoice.get("tax_amount") or 0),
        "total_amount": float(invoice.get("total_amount") or 0),
        "currency": invoice.get("currency"),
        "notes": invoice.get("notes"),
        "items": invoice.get("items") or [],
        "bank_account_id": int(invoice["bank_account_id"]) if invoice.get("bank_account_id") else None,
    }


def invoice_core_changed(old_invoice, new_data):
    old_values = invoice_core_values(old_invoice)
    new_values = invoice_core_values(new_data)
    return json.dumps(old_values, sort_keys=True, default=str) != json.dumps(new_values, sort_keys=True, default=str)


@app.route("/api/finance/accounts", methods=["GET", "POST"])
def api_finance_accounts():
    require_finance_access()
    db = get_db()
    ensure_default_accounts(db)

    if request.method == "POST":
        data = request.get_json() or {}
        payload, error = normalize_account_payload(data)
        if error:
            return jsonify({"error": error}), 400
        if db.accounts.find_one({"gl_code": payload["gl_code"]}):
            return jsonify({"error": "GL code already exists."}), 400
        if db.accounts.find_one({"name": {"$regex": f"^{re.escape(payload['name'])}$", "$options": "i"}}):
            return jsonify({"error": "Account name already exists."}), 400

        account_id = get_next_sequence_value("accounts")
        doc = {
            "id": account_id,
            **payload,
            "balance": 0,
            "is_system_default": 0,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
        }
        db.accounts.insert_one(doc)
        log_activity_async("Finance", "Chart of Account", account_id, "CREATE", new_data=doc, reference_number=payload["name"])
        return jsonify(json_ready({"account": {k: v for k, v in doc.items() if k != "_id"}}))

    accounts = list(db.accounts.find({}, {"_id": 0}).sort([("gl_code", 1), ("name", 1)]))
    return jsonify(json_ready({"accounts": accounts, "account_types": sorted(ACCOUNT_TYPES)}))


@app.route("/api/finance/accounts/<int:account_id>", methods=["PUT"])
def api_finance_account_detail(account_id):
    require_finance_access()
    db = get_db()
    ensure_default_accounts(db)

    existing = db.accounts.find_one({"id": account_id})
    if not existing:
        abort(404)

    data = request.get_json() or {}
    payload, error = normalize_account_payload(data, existing)
    if error:
        return jsonify({"error": error}), 400

    duplicate_code = db.accounts.find_one({"gl_code": payload["gl_code"], "id": {"$ne": account_id}})
    if duplicate_code:
        return jsonify({"error": "GL code already exists."}), 400
    duplicate_name = db.accounts.find_one({
        "name": {"$regex": f"^{re.escape(payload['name'])}$", "$options": "i"},
        "id": {"$ne": account_id},
    })
    if duplicate_name:
        return jsonify({"error": "Account name already exists."}), 400

    update_data = {**payload, "updated_at": datetime.now()}
    db.accounts.update_one({"id": account_id}, {"$set": update_data})
    updated = db.accounts.find_one({"id": account_id})
    log_activity_async("Finance", "Chart of Account", account_id, "UPDATE", old_data=existing, new_data=updated, reference_number=payload["name"])
    return jsonify(json_ready({"account": {k: v for k, v in updated.items() if k != "_id"}}))


@app.route("/api/finance/accounts/<int:account_id>/transactions")
def api_finance_account_transactions(account_id):
    require_finance_access()
    db = get_db()
    account = db.accounts.find_one({"id": account_id}, {"_id": 0})
    if not account:
        abort(404)

    transactions = list(db.transactions.aggregate([
        {"$match": {"account_id": account_id}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "vendors", "localField": "vendor_id", "foreignField": "id", "as": "vendor"}},
        {"$unwind": {"path": "$vendor", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "invoices", "localField": "invoice_id", "foreignField": "id", "as": "invoice"}},
        {"$unwind": {"path": "$invoice", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "customer_name": "$customer.company_name",
            "vendor_name": "$vendor.name",
            "project_name": "$project.project_name",
            "invoice_number": {"$ifNull": ["$invoice.invoice_number", "$invoice_number"]},
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]},
        }},
        {"$project": {"customer": 0, "vendor": 0, "project": 0, "invoice": 0, "_id": 0}},
        {"$sort": {"transaction_date": -1, "created_at": -1, "id": -1}},
    ]))
    return jsonify(json_ready({"account": account, "transactions": transactions}))


@app.route("/api/finance/invoices/receivable")
def api_finance_receivable_invoices():
    require_finance_access()
    db = get_db()
    customer_id = request.args.get("customer_id")
    account_id = request.args.get("account_id")
    if not customer_id:
        return jsonify(json_ready({"invoices": []}))

    query = {
        "customer_id": int(customer_id),
        "status": {"$in": INVOICE_RECEIPT_STATUSES},
    }
    if account_id:
        query["$or"] = [
            {"account_id": int(account_id)},
            {"account_id": {"$exists": False}},
            {"account_id": None},
        ]

    invoices = list(
        db.invoices.find(query, {"_id": 0}).sort([("issue_date", -1), ("invoice_number", -1)])
    )
    return jsonify(json_ready({"invoices": [invoice_receipt_summary(inv) for inv in invoices]}))


@app.route("/api/search")
def api_global_search():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    db = get_db()
    term = (request.args.get("q") or "").strip()
    if len(term) < 2:
        return jsonify({"results": []})

    normalized_term = term.lstrip("#")
    pattern = {"$regex": re.escape(term), "$options": "i"}
    normalized_pattern = {"$regex": re.escape(normalized_term), "$options": "i"}
    results = []

    def add_result(label, record_type, url, subtitle="", meta=""):
        results.append({
            "label": label,
            "type": record_type,
            "url": url,
            "subtitle": subtitle,
            "meta": meta,
        })

    for customer in db.customers.find(
        {"$or": [{"company_name": pattern}, {"contact_name": pattern}, {"email": pattern}, {"phone": pattern}]},
        {"_id": 0, "id": 1, "company_name": 1, "contact_name": 1, "email": 1},
    ).limit(6):
        add_result(
            customer.get("company_name") or f"Customer #{customer.get('id')}",
            "Customer",
            f"/customers/{customer['id']}",
            customer.get("contact_name") or customer.get("email") or "",
        )

    for project in db.projects.find(
        {"$or": [{"project_name": pattern}, {"owner": pattern}, {"status": pattern}]},
        {"_id": 0, "id": 1, "project_name": 1, "status": 1},
    ).limit(4):
        add_result(project.get("project_name") or f"Project #{project.get('id')}", "Project", f"/projects/{project['id']}", project.get("status") or "")

    for opportunity in db.opportunities.find(
        {"$or": [{"title": pattern}, {"opportunity_number": pattern}, {"stage": pattern}]},
        {"_id": 0, "id": 1, "title": 1, "opportunity_number": 1, "stage": 1},
    ).limit(4):
        add_result(
            opportunity.get("title") or opportunity.get("opportunity_number") or f"Opportunity #{opportunity.get('id')}",
            "Opportunity",
            f"/opportunities/{opportunity['id']}",
            opportunity.get("opportunity_number") or opportunity.get("stage") or "",
        )

    role_name = ""
    if user.get("role_id"):
        role = db.roles.find_one({"id": user.get("role_id")}, {"_id": 0, "name": 1})
        role_name = role.get("name") if role else ""
    is_admin_user = role_name in ["Admin", "System Administrator"]
    can_search_finance = is_admin_user or bool(user.get("has_finance_access"))

    if can_search_finance:
        for txn in db.transactions.find(
            {"$or": [{"id": normalized_pattern}, {"description": pattern}, {"category": pattern}, {"reference": pattern}]},
            {"_id": 0, "id": 1, "description": 1, "type": 1, "amount": 1, "currency": 1},
        ).limit(6):
            add_result(
                f"#{txn.get('id')}",
                "Transaction",
                f"/finance/transactions/{txn['id']}",
                txn.get("description") or txn.get("type") or "",
                f"{txn.get('currency', '')} {txn.get('amount', '')}".strip(),
            )

        for invoice in db.invoices.find(
            {"$or": [{"invoice_number": pattern}, {"status": pattern}, {"notes": pattern}]},
            {"_id": 0, "id": 1, "invoice_number": 1, "status": 1, "total_amount": 1, "currency": 1},
        ).limit(6):
            add_result(
                invoice.get("invoice_number") or f"Invoice #{invoice.get('id')}",
                "Invoice",
                f"/finance/invoices/{invoice['id']}",
                invoice.get("status") or "",
                f"{invoice.get('currency', '')} {invoice.get('total_amount', '')}".strip(),
            )

        if "ledger" in term.lower() or "transaction" in term.lower():
            add_result("Transaction Ledger", "Finance", "/finance/transactions", "All accounting entries")
            add_result("General Ledger Report", "Finance", "/finance/reports/general-ledger", "Ledger balances and journal view")
        if "account" in term.lower() or "chart" in term.lower() or "gl" in term.lower():
            add_result("Chart of Accounts", "Finance", "/finance/accounts", "GL codes and ledger accounts")

    return jsonify({"results": results[:20]})


@app.route("/api/setup")
def api_setup_home():
    db = get_db()
    remove_hidden_setup_object_metadata(db)
    visible_object_query = {"api_name": {"$nin": list(SETUP_HIDDEN_OBJECT_API_NAMES)}}
    metrics = {
        "users": db.app_users.count_documents({}),
        "roles": db.roles.count_documents({}),
        "objects": db.custom_objects.count_documents(visible_object_query),
        "fields": db.custom_fields.count_documents({}),
    }
    
    users = list(db.app_users.aggregate([
        {"$lookup": {"from": "roles", "localField": "role_id", "foreignField": "id", "as": "role"}},
        {"$unwind": {"path": "$role", "preserveNullAndEmptyArrays": True}},
        {"$project": {"_id": 0, "id": 1, "full_name": 1, "email": 1, "role_id": 1, "is_active": 1, "role_name": "$role.name"}},
        {"$sort": {"created_at": -1}},
        {"$limit": 8}
    ]))
    
    roles = list(db.roles.find({}, {"_id": 0, "id": 1, "name": 1, "description": 1}).sort("name", 1))
    
    objects = list(db.custom_objects.aggregate([
        {"$match": visible_object_query},
        {"$lookup": {"from": "custom_fields", "localField": "id", "foreignField": "object_id", "as": "fields"}},
        {"$addFields": {"field_count": {"$size": "$fields"}}},
        {"$project": {"_id": 0, "fields": 0}},
        {"$sort": {"is_standard": -1, "plural_label": 1}}
    ]))
    
    return jsonify(json_ready({"metrics": metrics, "users": users, "roles": roles, "objects": objects}))


@app.route("/api/setup/activity-logs", methods=["GET"])
def api_setup_activity_logs():
    actor = get_current_user()
    if not actor:
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    role = db.roles.find_one({"id": actor.get("role_id")})
    if not role or role["name"] not in ["Admin", "System Administrator"]:
        return jsonify({"error": "Forbidden"}), 403
        
    query = {}
    module_filter = request.args.get("module_name")
    if module_filter:
        query["module_name"] = module_filter
        
    entity_filter = request.args.get("entity_name")
    if entity_filter:
        query["entity_name"] = entity_filter
        
    action_filter = request.args.get("action_type")
    if action_filter:
        query["action_type"] = action_filter
        
    user_filter = request.args.get("user_name")
    if user_filter:
        query["user_name"] = {"$regex": user_filter, "$options": "i"}
        
    record_filter = request.args.get("record_id")
    if record_filter:
        try:
            query["record_id"] = int(record_filter)
        except ValueError:
            pass
            
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        limit = 20
        
    try:
        skip = int(request.args.get("skip", 0))
    except ValueError:
        skip = 0
        
    total = db.activity_logs.count_documents(query)
    logs = list(db.activity_logs.find(query, {"_id": 0}).sort("timestamp", pymongo.DESCENDING).skip(skip).limit(limit))
    
    return jsonify(json_ready({
        "logs": logs,
        "total": total,
        "skip": skip,
        "limit": limit
    }))


@app.route("/api/setup/users", methods=["GET", "POST"])
def api_setup_users():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        vault_access_code = (data.get("vault_access_code") or "").strip()
        if data.get("has_vault_access") and len(vault_access_code) < 4:
            return jsonify({"error": "Vault access code must be at least 4 characters."}), 400
        user_id = get_next_sequence_value("app_users")
        db.app_users.insert_one({
            "id": user_id,
            "full_name": data["full_name"],
            "email": data["email"],
            "password_hash": generate_password_hash(data["password"]),
            "role_id": data.get("role_id") or None,
            "is_active": data.get("is_active", True),
            "has_treasury_access": 1 if data.get("has_treasury_access") else 0,
            "has_finance_access": 1 if data.get("has_finance_access") else 0,
            "has_vault_access": 1 if data.get("has_vault_access") else 0,
            "vault_access_code_hash": generate_password_hash(vault_access_code) if vault_access_code else None,
            "requires_password_change": True,
            "created_at": datetime.now()
        })
        return jsonify({"id": user_id})
        
    users = list(db.app_users.aggregate([
        {"$lookup": {"from": "roles", "localField": "role_id", "foreignField": "id", "as": "role"}},
        {"$unwind": {"path": "$role", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"has_vault_access_code": {"$ne": [{"$ifNull": ["$vault_access_code_hash", None]}, None]}}},
        {"$project": {"_id": 0, "password_hash": 0, "vault_access_code_hash": 0}},
        {"$addFields": {"role_name": "$role.name"}},
        {"$project": {"role": 0}},
        {"$sort": {"created_at": -1}}
    ]))
    return jsonify(json_ready({"users": users}))


@app.route("/api/setup/users/<int:user_id>", methods=["GET", "PUT"])
def api_setup_user(user_id):
    db = get_db()
    raw_user = db.app_users.find_one({"id": user_id})
    user = db.app_users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0, "vault_access_code_hash": 0})
    if not user:
        abort(404)
    user["has_vault_access_code"] = bool(raw_user.get("vault_access_code_hash"))
        
    if request.method == "PUT":
        data = request.get_json()
        existing_user = db.app_users.find_one({"id": user_id})
        vault_access_code = (data.get("vault_access_code") or "").strip()
        has_vault_access = 1 if data.get("has_vault_access") else 0
        if has_vault_access and not existing_user.get("vault_access_code_hash") and len(vault_access_code) < 4:
            return jsonify({"error": "Vault access code must be set before enabling Vault access."}), 400
        if vault_access_code and len(vault_access_code) < 4:
            return jsonify({"error": "Vault access code must be at least 4 characters."}), 400
        update_data = {
            "full_name": data["full_name"],
            "email": data["email"],
            "role_id": data.get("role_id") or None,
            "is_active": data.get("is_active", True),
            "has_treasury_access": 1 if data.get("has_treasury_access") else 0,
            "has_finance_access": 1 if data.get("has_finance_access") else 0,
            "has_vault_access": has_vault_access,
        }
        if data.get("password"):
            update_data["password_hash"] = generate_password_hash(data["password"])
        if vault_access_code:
            update_data["vault_access_code_hash"] = generate_password_hash(vault_access_code)
            if session.get("vault_unlocked_user_id") == user_id:
                session.pop("vault_unlocked_user_id", None)
            
        db.app_users.update_one({"id": user_id}, {"$set": update_data})
        return jsonify({"success": True})
        
    return jsonify(json_ready(user))


@app.route("/api/setup/users/<int:user_id>/reset-password", methods=["POST"])
def api_setup_reset_password(user_id):
    actor = get_current_user()
    if not actor:
        return jsonify({"error": "Unauthorized"}), 401
        
    db = get_db()
    role = db.roles.find_one({"id": actor.get("role_id")})
    if not role or role["name"] not in ["Admin", "System Administrator"]:
        return jsonify({"error": "Forbidden"}), 403
        
    data = request.get_json()
    new_password = data.get("password")
    if not new_password:
        return jsonify({"error": "Password is required"}), 400
        
    is_valid, msg = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"error": msg}), 400
        
    result = db.app_users.update_one(
        {"id": user_id},
        {"$set": {
            "password_hash": generate_password_hash(new_password),
            "requires_password_change": True
        }}
    )
    if result.matched_count == 0:
        return jsonify({"error": "User not found"}), 404
        
    return jsonify({"success": True})


@app.route("/api/setup/roles", methods=["GET", "POST"])
def api_setup_roles():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        role_id = get_next_sequence_value("roles")
        db.roles.insert_one({
            "id": role_id,
            "name": data["name"],
            "description": data.get("description"),
            "created_at": datetime.now()
        })
        return jsonify({"id": role_id})
        
    roles = list(db.roles.find({}, {"_id": 0}).sort("name", 1))
    return jsonify(json_ready({"roles": roles}))


@app.route("/api/setup/roles/<int:role_id>", methods=["PUT", "DELETE"])
def api_setup_role(role_id):
    db = get_db()
    if request.method == "DELETE":
        db.roles.delete_one({"id": role_id})
        db.app_users.update_many({"role_id": role_id}, {"$set": {"role_id": None}})
        db.field_level_security.delete_many({"role_id": role_id})
        return jsonify({"success": True})
        
    data = request.get_json()
    db.roles.update_one(
        {"id": role_id},
        {"$set": {"name": data["name"], "description": data.get("description")}}
    )
    return jsonify({"success": True})


@app.route("/api/setup/roles/<int:role_id>/security", methods=["GET"])
def api_setup_role_security(role_id):
    db = get_db()
    remove_hidden_setup_object_metadata(db)
    objects = list(
        db.custom_objects.find(
            {"api_name": {"$nin": list(SETUP_HIDDEN_OBJECT_API_NAMES)}},
            {"_id": 0}
        ).sort("plural_label", 1)
    )
    return jsonify(json_ready({"objects": objects}))


@app.route("/api/setup/roles/<int:role_id>/security/<int:object_id>", methods=["GET", "POST"])
def api_setup_role_object_security(role_id, object_id):
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        db.field_level_security.delete_many({"role_id": role_id, "object_id": object_id})
        if data.get("fields"):
            docs = []
            for field in data["fields"]:
                docs.append({
                    "role_id": role_id,
                    "object_id": object_id,
                    "field_id": field["id"],
                    "can_view": field.get("can_view", False),
                    "can_edit": field.get("can_edit", False)
                })
            db.field_level_security.insert_many(docs)
        return jsonify({"success": True})

    fields = list(db.custom_fields.find({"object_id": object_id}, {"_id": 0}))
    fls = list(db.field_level_security.find({"role_id": role_id, "object_id": object_id}, {"_id": 0}))
    
    fls_map = {item["field_id"]: item for item in fls}
    
    for f in fields:
        sec = fls_map.get(f["id"])
        if sec:
            f["can_view"] = bool(sec.get("can_view"))
            f["can_edit"] = bool(sec.get("can_edit"))
        else:
            f["can_view"] = True
            f["can_edit"] = True
            
    return jsonify(json_ready({"fields": fields}))

@app.route("/api/setup/objects", methods=["GET", "POST"])
def api_setup_objects():
    db = get_db()
    remove_hidden_setup_object_metadata(db)
    if request.method == "POST":
        data = request.get_json()
        api_name = slugify_api_name(data["plural_label"])
        if api_name in SETUP_HIDDEN_OBJECT_API_NAMES:
            return jsonify({"error": "This object name is reserved by the system"}), 400
        
        # Check if api_name exists
        if db.custom_objects.find_one({"api_name": api_name}):
            return jsonify({"error": "Object with this name already exists"}), 400
            
        object_id = get_next_sequence_value("custom_objects")
        insert_data = {
            "id": object_id,
            "label": data["label"],
            "plural_label": data["plural_label"],
            "api_name": api_name,
            "is_standard": 0,
            "storage_table": None,
            "description": data.get("description"),
            "created_at": datetime.now()
        }
        db.custom_objects.insert_one(insert_data)
        log_activity_async("Setup", "Custom Object", object_id, "CREATE", new_data=insert_data)
        return jsonify({"id": object_id, "api_name": api_name})
        
    objects = list(db.custom_objects.aggregate([
        {"$match": {"api_name": {"$nin": list(SETUP_HIDDEN_OBJECT_API_NAMES)}}},
        {"$lookup": {"from": "custom_fields", "localField": "id", "foreignField": "object_id", "as": "fields"}},
        {"$addFields": {"field_count": {"$size": "$fields"}}},
        {"$project": {"_id": 0, "fields": 0}},
        {"$sort": {"is_standard": -1, "plural_label": 1}}
    ]))
    return jsonify(json_ready({"objects": objects}))


@app.route("/api/setup/objects/<string:api_name>", methods=["GET"])
def api_setup_object_detail(api_name):
    if api_name in SETUP_HIDDEN_OBJECT_API_NAMES:
        abort(404)
    db = get_db()
    remove_hidden_setup_object_metadata(db)
    obj = db.custom_objects.find_one({"api_name": api_name}, {"_id": 0})
    if not obj:
        abort(404)
    fields = list(db.custom_fields.find({"object_id": obj["id"]}, {"_id": 0}))
    return jsonify(json_ready({"object": obj, "fields": fields}))


@app.route("/api/setup/objects/<int:object_id>/fields", methods=["POST"])
def api_setup_create_field(object_id):
    db = get_db()
    data = request.get_json()
    field_api_name = slugify_api_name(data["label"], suffix="_c")
    
    # Check if exists
    if db.custom_fields.find_one({"object_id": object_id, "api_name": field_api_name}):
        return jsonify({"error": "Field with this label already exists on this object"}), 400
        
    field_id = get_next_sequence_value("custom_fields")
    insert_data = {
        "id": field_id,
        "object_id": object_id,
        "label": data["label"],
        "api_name": field_api_name,
        "is_native": 0,
        "native_column": None,
        "field_type": data["field_type"],
        "picklist_options": data.get("picklist_options"),
        "is_required": 1 if data.get("is_required") else 0,
        "created_at": datetime.now()
    }
    db.custom_fields.insert_one(insert_data)
    log_activity_async("Setup", "Custom Field", field_id, "CREATE", new_data=insert_data)
    return jsonify({"id": field_id})


@app.route("/api/setup/fields/<int:field_id>", methods=["PUT", "DELETE"])
def api_setup_field_detail(field_id):
    db = get_db()
    field = db.custom_fields.find_one({"id": field_id})
    if not field:
        abort(404)
        
    if request.method == "DELETE":
        if field.get("is_native"):
            return jsonify({"error": "Cannot delete a native system field."}), 400
        db.custom_fields.delete_one({"id": field_id})
        db.field_level_security.delete_many({"field_id": field_id})
        log_activity_async("Setup", "Custom Field", field_id, "DELETE", old_data=field)
        return jsonify({"success": True})
        
    data = request.get_json()
    update_data = {
        "label": data["label"],
        "field_type": data["field_type"],
        "picklist_options": data.get("picklist_options"),
        "is_required": 1 if data.get("is_required") else 0
    }
    old_field = db.custom_fields.find_one({"id": field_id})
    db.custom_fields.update_one({"id": field_id}, {"$set": update_data})
    new_field = db.custom_fields.find_one({"id": field_id})
    log_activity_async("Setup", "Custom Field", field_id, "UPDATE", old_data=old_field, new_data=new_field)
    return jsonify({"success": True})


@app.route("/api/setup/objects/<int:object_id>", methods=["PUT"])
def api_setup_object(object_id):
    db = get_db()
    obj = db.custom_objects.find_one({"id": object_id})
    if not obj:
        abort(404)
        
    if obj.get("is_standard"):
        return jsonify({"error": "Cannot edit standard objects"}), 400
        
    data = request.get_json()
    old_obj = db.custom_objects.find_one({"id": object_id})
    db.custom_objects.update_one(
        {"id": object_id},
        {"$set": {
            "label": data["label"],
            "plural_label": data["plural_label"],
            "description": data.get("description")
        }}
    )
    new_obj = db.custom_objects.find_one({"id": object_id})
    log_activity_async("Setup", "Custom Object", object_id, "UPDATE", old_data=old_obj, new_data=new_obj)
    return jsonify({"success": True})

@app.route("/api/customers", methods=["GET", "POST"])
def api_customers():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        validation_error = validate_profile_master_fields(db, data)
        if validation_error:
            return jsonify({"error": validation_error}), 400
        customer_id = get_next_sequence_value("customers")
        actor, actor_id, actor_name = audit_actor()
        
        insert_data = {
            "id": customer_id,
            "company_name": data.get("company_name"),
            "contact_name": data.get("contact_name"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "industry": data.get("industry"),
            "status": data.get("status", "Lead"),
            "notes": data.get("notes"),
            "billing_address": data.get("billing_address"),
            "address_line_1": data.get("address_line_1"),
            "address_line_2": data.get("address_line_2"),
            "city": data.get("city"),
            "pincode": data.get("pincode"),
            "state": data.get("state"),
            "country": data.get("country"),
            "registration_type": data.get("registration_type"),
            "payment_terms": data.get("payment_terms"),
            "payment_mode": data.get("payment_mode"),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge all other dynamic custom or standard fields
        merge_client_fields(insert_data, data)
                
        db.customers.insert_one(insert_data)
        log_activity_async("Customers", "Customer", customer_id, "CREATE", new_data=insert_data, reference_number=insert_data.get("company_name"))
        customer = db.customers.find_one({"id": customer_id}, {"_id": 0})
        return jsonify(json_ready({"customer": customer}))
        
    customers = list(db.customers.find({}, {"_id": 0}).sort("created_at", -1))
    import json
    customer_obj = db.custom_objects.find_one({"api_name": "customers"})
    customer_status_field = db.custom_fields.find_one({"object_id": customer_obj["id"], "api_name": "status"}) if customer_obj else None
    customer_statuses = json.loads(customer_status_field["picklist_options"]) if customer_status_field and customer_status_field.get("picklist_options") else CUSTOMER_STATUSES
    
    # Fetch fields configured for the Customer object
    fields = []
    if customer_obj:
        fields = get_fields_for_user(customer_obj["id"])
        
    return jsonify(json_ready({
        "customers": customers,
        "statuses": customer_statuses,
        "fields": fields
    }))


@app.route("/api/customers/<int:customer_id>", methods=["GET", "PUT"])
def api_customer_detail(customer_id):
    db = get_db()
    customer = db.customers.find_one({"id": customer_id}, {"_id": 0})
    if not customer:
        abort(404)
        
    if request.method == "PUT":
        data = request.get_json()
        validation_error = validate_profile_master_fields(db, data)
        if validation_error:
            return jsonify({"error": validation_error}), 400
        actor, actor_id, actor_name = audit_actor()
        update_data = {
            "company_name": data.get("company_name"),
            "contact_name": data.get("contact_name"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "industry": data.get("industry"),
            "status": data.get("status"),
            "notes": data.get("notes"),
            "billing_address": data.get("billing_address"),
            "address_line_1": data.get("address_line_1"),
            "address_line_2": data.get("address_line_2"),
            "city": data.get("city"),
            "pincode": data.get("pincode"),
            "state": data.get("state"),
            "country": data.get("country"),
            "registration_type": data.get("registration_type"),
            "payment_terms": data.get("payment_terms"),
            "payment_mode": data.get("payment_mode"),
            "updated_at": datetime.now(),
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge all other dynamic fields
        merge_client_fields(update_data, data)
                
        old_customer = db.customers.find_one({"id": customer_id}, {"_id": 0})
        db.customers.update_one(
            {"id": customer_id},
            {"$set": update_data}
        )
        new_customer = db.customers.find_one({"id": customer_id}, {"_id": 0})
        log_activity_async("Customers", "Customer", customer_id, "UPDATE", old_data=old_customer, new_data=new_customer, reference_number=new_customer.get("company_name"))
        return jsonify({"success": True})
        
    # Fetch related
    opportunities = list(db.opportunities.find({"customer_id": customer_id}, {"_id": 0}))
    projects = list(db.projects.find({"customer_id": customer_id}, {"_id": 0}))
    
    # Fetch fields configured for the Customer object
    customer_obj = db.custom_objects.find_one({"api_name": "customers"})
    fields = []
    if customer_obj:
        fields = get_fields_for_user(customer_obj["id"])
        
    return jsonify(json_ready({
        "customer": customer,
        "opportunities": opportunities,
        "projects": projects,
        "fields": fields
    }))

@app.route("/api/opportunities", methods=["GET", "POST"])
def api_opportunities():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        opportunity_id = get_next_sequence_value("opportunities")
        actor, actor_id, actor_name = audit_actor()
        
        country = data.get("country") or data.get("country_c") or ""
        country_prefix = (country[:2].upper().ljust(2, 'X')) if country else "XX"
        now = datetime.now()
        prefix = f"{country_prefix}{now.strftime('%Y%m')}"
        
        opps_with_prefix = list(db.opportunities.find({"opportunity_number": {"$regex": f"^{prefix}"}}, {"_id": 0, "opportunity_number": 1}))
        max_seq = 0
        for opp in opps_with_prefix:
            num_str = opp.get("opportunity_number", "")
            if num_str and num_str.startswith(prefix):
                seq_str = num_str[len(prefix):]
                if seq_str.isdigit():
                    max_seq = max(max_seq, int(seq_str))
                    
        opportunity_number = f"{prefix}{max_seq + 1:03d}"
        
        insert_data = {
            "id": opportunity_id,
            "title": data.get("title"),
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "country": data.get("country") or data.get("country_c"),
            "opportunity_number": opportunity_number,
            "value": float(data.get("value")) if data.get("value") else 0.0,
            "currency": data.get("currency", "INR"),
            "stage": data.get("stage", "Draft"),
            "expected_close": data.get("expected_close"),
            "requirements": data.get("requirements"),
            "next_action": data.get("next_action"),
            "notes": data.get("notes"),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        merge_client_fields(insert_data, data)
                
        db.opportunities.insert_one(insert_data)
        log_activity_async("Opportunities", "Opportunity", opportunity_id, "CREATE", new_data=insert_data, reference_number=insert_data.get("opportunity_number"))
        
        opps = list(db.opportunities.aggregate([
            {"$match": {"id": opportunity_id}},
            {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
            {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
            {"$project": {"_id": 0, "customer": 0}},
            {"$addFields": {"company_name": "$customer.company_name"}}
        ]))
        return jsonify(json_ready({"opportunity": opps[0]}))
        
    opportunities = list(db.opportunities.aggregate([
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"company_name": "$customer.company_name"}},
        {"$project": {"_id": 0, "customer": 0}},
        {"$sort": {"updated_at": -1}}
    ]))
    import json
    opp_obj = db.custom_objects.find_one({"api_name": "opportunities"})
    opp_stage_field = db.custom_fields.find_one({"object_id": opp_obj["id"], "api_name": "stage"}) if opp_obj else None
    opportunity_stages = json.loads(opp_stage_field["picklist_options"]) if opp_stage_field and opp_stage_field.get("picklist_options") else OPPORTUNITY_STAGES
    
    # Fetch fields configured for the Opportunity object
    fields = []
    if opp_obj:
        fields = get_fields_for_user(opp_obj["id"])
        
    # Also fetch currencies globally
    currencies_records = list(db.currencies.find({}, {"_id": 0, "code": 1}))
    currencies_list = currencies_records if currencies_records else CURRENCIES
    
    return jsonify(json_ready({
        "opportunities": opportunities, 
        "stages": opportunity_stages, 
        "currencies": currencies_list,
        "fields": fields
    }))


@app.route("/api/opportunities/<int:opportunity_id>", methods=["GET", "PUT"])
def api_opportunity_detail(opportunity_id):
    db = get_db()
    
    if request.method == "PUT":
        data = request.get_json()
        actor, actor_id, actor_name = audit_actor()
        update_data = {
            "title": data.get("title"),
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "country": data.get("country") or data.get("country_c"),
            "opportunity_number": data.get("opportunity_number"),
            "value": float(data.get("value")) if data.get("value") else 0.0,
            "currency": data.get("currency"),
            "stage": data.get("stage"),
            "expected_close": data.get("expected_close"),
            "requirements": data.get("requirements"),
            "next_action": data.get("next_action"),
            "notes": data.get("notes"),
            "updated_at": datetime.now(),
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        merge_client_fields(update_data, data)
                
        old_opportunity = db.opportunities.find_one({"id": opportunity_id}, {"_id": 0})
        db.opportunities.update_one(
            {"id": opportunity_id},
            {"$set": update_data}
        )
        new_opportunity = db.opportunities.find_one({"id": opportunity_id}, {"_id": 0})
        log_activity_async("Opportunities", "Opportunity", opportunity_id, "UPDATE", old_data=old_opportunity, new_data=new_opportunity, reference_number=new_opportunity.get("opportunity_number"))
        return jsonify({"success": True})
        
    opps = list(db.opportunities.aggregate([
        {"$match": {"id": opportunity_id}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"company_name": "$customer.company_name"}},
        {"$project": {"_id": 0, "customer": 0}}
    ]))
    if not opps:
        abort(404)
        
    projects = list(db.projects.find({"opportunity_id": opportunity_id}, {"_id": 0}))
    
    # Fetch fields configured for the Opportunity object
    opp_obj = db.custom_objects.find_one({"api_name": "opportunities"})
    fields = []
    if opp_obj:
        fields = get_fields_for_user(opp_obj["id"])
        
    return jsonify(json_ready({
        "opportunity": opps[0],
        "projects": projects,
        "fields": fields
    }))

@app.route("/api/projects", methods=["GET", "POST"])
def api_projects():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        project_id = get_next_sequence_value("projects")
        actor, actor_id, actor_name = audit_actor()
        
        insert_data = {
            "id": project_id,
            "project_name": data.get("project_name"),
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "opportunity_id": int(data.get("opportunity_id")) if data.get("opportunity_id") else None,
            "status": data.get("status", "Planning"),
            "client_requirements": data.get("client_requirements"),
            "delivery_timeline": data.get("delivery_timeline"),
            "product_delivery_status": data.get("product_delivery_status"),
            "owner": data.get("owner"),
            "last_update": data.get("last_update"),
            "budget": float(data.get("budget")) if data.get("budget") else 0.0,
            "currency": data.get("currency", "INR"),
            "notes": data.get("notes"),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        merge_client_fields(insert_data, data)
                
        db.projects.insert_one(insert_data)
        log_activity_async("Projects", "Project", project_id, "CREATE", new_data=insert_data, reference_number=insert_data.get("project_name"))
        
        projs = list(db.projects.aggregate([
            {"$match": {"id": project_id}},
            {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
            {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
            {"$project": {"_id": 0, "customer": 0}},
            {"$addFields": {"company_name": "$customer.company_name"}}
        ]))
        return jsonify(json_ready({"project": projs[0]}))
        
    projects = list(db.projects.aggregate([
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "opportunities", "localField": "opportunity_id", "foreignField": "id", "as": "opportunity"}},
        {"$unwind": {"path": "$opportunity", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "company_name": "$customer.company_name",
            "opportunity_title": "$opportunity.title"
        }},
        {"$project": {"_id": 0, "customer": 0, "opportunity": 0}},
        {"$sort": {"updated_at": -1}}
    ]))
    import json
    proj_obj = db.custom_objects.find_one({"api_name": "projects"})
    proj_status_field = db.custom_fields.find_one({"object_id": proj_obj["id"], "api_name": "status"}) if proj_obj else None
    project_statuses = json.loads(proj_status_field["picklist_options"]) if proj_status_field and proj_status_field.get("picklist_options") else PROJECT_STATUSES
    
    # Fetch fields configured for the Project object
    fields = []
    if proj_obj:
        fields = get_fields_for_user(proj_obj["id"])
        
    # Fetch currencies
    currencies_records = list(db.currencies.find({}, {"_id": 0, "code": 1}))
    currencies_list = currencies_records if currencies_records else CURRENCIES
    
    return jsonify(json_ready({
        "projects": projects, 
        "statuses": project_statuses, 
        "currencies": currencies_list,
        "fields": fields
    }))


@app.route("/api/projects/<int:project_id>", methods=["GET", "PUT"])
def api_project_detail(project_id):
    db = get_db()
    
    if request.method == "PUT":
        data = request.get_json()
        actor, actor_id, actor_name = audit_actor()
        update_data = {
            "project_name": data.get("project_name"),
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "opportunity_id": int(data.get("opportunity_id")) if data.get("opportunity_id") else None,
            "status": data.get("status"),
            "client_requirements": data.get("client_requirements"),
            "delivery_timeline": data.get("delivery_timeline"),
            "product_delivery_status": data.get("product_delivery_status"),
            "owner": data.get("owner"),
            "last_update": data.get("last_update"),
            "budget": float(data.get("budget")) if data.get("budget") else 0.0,
            "currency": data.get("currency"),
            "notes": data.get("notes"),
            "updated_at": datetime.now(),
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        merge_client_fields(update_data, data)
                
        old_project = db.projects.find_one({"id": project_id}, {"_id": 0})
        db.projects.update_one(
            {"id": project_id},
            {"$set": update_data}
        )
        new_project = db.projects.find_one({"id": project_id}, {"_id": 0})
        log_activity_async("Projects", "Project", project_id, "UPDATE", old_data=old_project, new_data=new_project, reference_number=new_project.get("project_name"))
        return jsonify({"success": True})
        
    projects = list(db.projects.aggregate([
        {"$match": {"id": project_id}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"company_name": "$customer.company_name"}},
        {"$project": {"_id": 0, "customer": 0}}
    ]))
    if not projects:
        abort(404)
        
    # attach opportunity title
    proj = projects[0]
    if proj.get("opportunity_id"):
        opp = db.opportunities.find_one({"id": proj["opportunity_id"]})
        if opp:
            proj["opportunity_title"] = opp.get("title")
            
    # Fetch fields configured for the Project object
    proj_obj = db.custom_objects.find_one({"api_name": "projects"})
    fields = []
    if proj_obj:
        fields = get_fields_for_user(proj_obj["id"])
        
    return jsonify(json_ready({
        "project": proj,
        "fields": fields
    }))


@app.route("/api/finance/vendors", methods=["GET", "POST"])
def api_finance_vendors():
    require_finance_access()
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        validation_error = validate_profile_master_fields(db, data, include_supplier_fields=True)
        if validation_error:
            return jsonify({"error": validation_error}), 400
        category = data.get("category") or "Both"
        if category not in VENDOR_CATEGORIES:
            return jsonify({"error": "Vendor category must be Supply, Service, or Both."}), 400
        vendor_id = get_next_sequence_value("vendors")
        actor, actor_id, actor_name = audit_actor()
        
        insert_data = {
            "id": vendor_id,
            "name": data.get("name"),
            "contact_person": data.get("contact_person"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "category": category,
            "address_line_1": data.get("address_line_1"),
            "address_line_2": data.get("address_line_2"),
            "city": data.get("city"),
            "pincode": data.get("pincode"),
            "state": data.get("state"),
            "country": data.get("country"),
            "registration_type": data.get("registration_type"),
            "supplier_category": data.get("supplier_category"),
            "payment_terms": data.get("payment_terms"),
            "payment_mode": data.get("payment_mode"),
            "notes": data.get("notes"),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        merge_client_fields(insert_data, data)
                
        db.vendors.insert_one(insert_data)
        log_activity_async("Finance", "Vendor", vendor_id, "CREATE", new_data=insert_data, reference_number=insert_data.get("name"))
        
        vendor = db.vendors.find_one({"id": vendor_id}, {"_id": 0})
        return jsonify(json_ready({"vendor": vendor}))
        
    vendors = list(db.vendors.find({}, {"_id": 0}).sort("created_at", -1))
    
    # Fetch fields configured for the Vendor object
    vendor_obj = db.custom_objects.find_one({"api_name": "vendors"})
    fields = []
    if vendor_obj:
        fields = get_fields_for_user(vendor_obj["id"])
        
    return jsonify(json_ready({
        "vendors": vendors,
        "fields": fields
    }))


@app.route("/api/finance/vendors/<int:vendor_id>", methods=["GET", "PUT"])
def api_finance_vendor_detail(vendor_id):
    require_finance_access()
    db = get_db()
    vendor = db.vendors.find_one({"id": vendor_id}, {"_id": 0})
    if not vendor:
        abort(404)
        
    if request.method == "PUT":
        data = request.get_json()
        validation_error = validate_profile_master_fields(db, data, include_supplier_fields=True)
        if validation_error:
            return jsonify({"error": validation_error}), 400
        category = data.get("category") or "Both"
        if category not in VENDOR_CATEGORIES:
            return jsonify({"error": "Vendor category must be Supply, Service, or Both."}), 400
        actor, actor_id, actor_name = audit_actor()
        update_data = {
            "name": data.get("name"),
            "contact_person": data.get("contact_person"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "category": category,
            "address_line_1": data.get("address_line_1"),
            "address_line_2": data.get("address_line_2"),
            "city": data.get("city"),
            "pincode": data.get("pincode"),
            "state": data.get("state"),
            "country": data.get("country"),
            "registration_type": data.get("registration_type"),
            "supplier_category": data.get("supplier_category"),
            "payment_terms": data.get("payment_terms"),
            "payment_mode": data.get("payment_mode"),
            "notes": data.get("notes"),
            "updated_at": datetime.now(),
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        merge_client_fields(update_data, data)
                
        old_vendor = db.vendors.find_one({"id": vendor_id}, {"_id": 0})
        db.vendors.update_one(
            {"id": vendor_id},
            {"$set": update_data}
        )
        new_vendor = db.vendors.find_one({"id": vendor_id}, {"_id": 0})
        log_activity_async("Finance", "Vendor", vendor_id, "UPDATE", old_data=old_vendor, new_data=new_vendor, reference_number=new_vendor.get("name"))
        return jsonify({"success": True})
        
    # Fetch fields configured for the Vendor object
    vendor_obj = db.custom_objects.find_one({"api_name": "vendors"})
    fields = []
    if vendor_obj:
        fields = get_fields_for_user(vendor_obj["id"])
        
    return jsonify(json_ready({
        "vendor": vendor,
        "fields": fields
    }))


@app.route("/api/finance")
def api_finance_dashboard():
    require_finance_access()
    db = get_db()
    
    # Load exchange rates
    inr_rate = 95.0
    setting = db.system_settings.find_one({"key_name": "exchange_rates"})
    if setting and setting.get("value"):
        try:
            rates_data = json.loads(setting["value"])
            inr_rate = rates_data.get("INR", {}).get("default", 95.0)
        except Exception:
            pass

    transactions = list(db.transactions.find({"status": {"$ne": "Reversed"}}))
    
    total_revenue_usd = 0.0
    total_revenue_inr = 0.0
    total_expenses_usd = 0.0
    total_expenses_inr = 0.0

    for tx in transactions:
        amount = float(tx.get("total_amount") or tx.get("amount") or 0.0)
        currency = tx.get("currency", "USD")
        
        tx_date = tx.get("transaction_date") or tx.get("date")
        month = tx_date[:7] if tx_date and len(tx_date) >= 7 else ""
        current_rate = inr_rate
        if month and setting and setting.get("value"):
            try:
                rates_data = json.loads(setting["value"])
                monthly_rates = rates_data.get("INR", {}).get("monthly", {})
                if month in monthly_rates:
                    current_rate = monthly_rates[month]
            except Exception:
                pass
                
        if currency == "USD":
            amt_usd = amount
            amt_inr = amount * current_rate
        elif currency == "INR":
            amt_usd = amount / current_rate
            amt_inr = amount
        else:
            # Fallback for EUR/GBP etc.
            amt_usd = amount
            amt_inr = amount * current_rate
            
        tx_type = tx.get("type")
        if tx_type in ["Credit", "Income"]:
            total_revenue_usd += amt_usd
            total_revenue_inr += amt_inr
        elif tx_type in ["Debit", "Expense"]:
            total_expenses_usd += amt_usd
            total_expenses_inr += amt_inr
            
    unpaid_invoices_count = db.invoices.count_documents({"status": {"$in": ["Draft", "Sent", "Partially Paid"]}})
    
    metrics = {
        "total_revenue": total_revenue_usd,
        "total_expenses": total_expenses_usd,
        "net_profit": total_revenue_usd - total_expenses_usd,
        "bank_balance": total_revenue_usd - total_expenses_usd,
        "cash_on_hand": 0.0,
        "unpaid_invoices": unpaid_invoices_count,
        "total_revenue_inr": total_revenue_inr,
        "total_expenses_inr": total_expenses_inr,
        "net_profit_inr": total_revenue_inr - total_expenses_inr,
        "bank_balance_inr": total_revenue_inr - total_expenses_inr,
        "cash_on_hand_inr": 0.0,
    }
    
    recent_transactions = list(db.transactions.aggregate([
        {"$match": {"status": {"$ne": "Reversed"}}},
        {"$sort": {"date": -1}},
        {"$limit": 6},
        {"$lookup": {"from": "accounts", "localField": "account_id", "foreignField": "id", "as": "account"}},
        {"$unwind": {"path": "$account", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"account_name": "$account.name"}},
        {"$project": {"account": 0, "_id": 0}}
    ]))
    
    invoices = list(db.invoices.aggregate([
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"customer_name": "$customer.company_name"}},
        {"$project": {"customer": 0, "_id": 0}},
        {"$sort": {"issue_date": -1}},
        {"$limit": 6}
    ]))
    
    return jsonify(
        json_ready(
            {
                "metrics": metrics,
                "recent_transactions": recent_transactions,
                "invoices": invoices,
                "currency_symbols": CURRENCY_SYMBOLS,
            }
        )
    )

@app.route("/api/finance/transactions", methods=["GET", "POST"])
def api_finance_transactions():
    require_finance_access()
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        seq = get_next_sequence_value("transactions")
        transaction_id = f"TXN{seq:03d}"
        
        amount = float(data.get("amount") or 0)
        cgst_percent = float(data.get("cgst_percent") or 0)
        igst_percent = float(data.get("igst_percent") or 0)
        tds_percent = float(data.get("tds_percent") or 0)
        
        cgst_amount = amount * (cgst_percent / 100.0)
        igst_amount = amount * (igst_percent / 100.0)
        tds_amount = amount * (tds_percent / 100.0)
        
        total_amount = amount + cgst_amount + igst_amount - tds_amount
        
        date_val = data.get("transaction_date") or data.get("date")
        if not date_val:
            date_val = datetime.now().strftime("%Y-%m-%d")

        account_id = int(data.get("account_id")) if data.get("account_id") else None
        customer_id = int(data.get("customer_id")) if data.get("customer_id") else None
        selected_account = db.accounts.find_one({"id": account_id}) if account_id else None
        transaction_type = data.get("type", "Income")
        if account_id and not account_available_for_transaction(selected_account, transaction_type):
            return jsonify({"error": "Selected account is not available for this transaction type."}), 400
        invoice_id = int(data.get("invoice_id")) if data.get("invoice_id") else None
        invoice_number = data.get("invoice_number")
        needs_invoice = transaction_type == "Income" and selected_account and selected_account.get("name") == "Sales Revenue"
        if needs_invoice:
            if not customer_id:
                return jsonify({"error": "Customer is required for Sales Revenue receipts."}), 400
            if not invoice_id:
                return jsonify({"error": "Invoice number is required for Sales Revenue receipts."}), 400
            invoice = db.invoices.find_one({
                "id": invoice_id,
                "customer_id": customer_id,
                "status": {"$in": INVOICE_RECEIPT_STATUSES},
                "$or": [
                    {"account_id": account_id},
                    {"account_id": {"$exists": False}},
                    {"account_id": None},
                ],
            })
            if not invoice:
                return jsonify({"error": "Select an approved, partially paid, or paid invoice for this customer and account."}), 400
            invoice_number = invoice.get("invoice_number")
        else:
            invoice_id = None
            invoice_number = None

        category = data.get("category")
        expense_claim_id = safe_int(data.get("expense_claim_id"))
        is_employee_claim_account = (
            transaction_type == "Expense"
            and selected_account
            and (
                str(selected_account.get("gl_code") or "").strip() == "7010"
                or selected_account.get("name") == "Employee Claims"
            )
        )
        linked_claim = None
        if is_employee_claim_account:
            if not expense_claim_id:
                return jsonify({"error": "Select an approved employee claim before posting to GL 7010 - Employee Claims."}), 400
            linked_claim = db.expense_claims.find_one({
                "id": expense_claim_id,
                "status": {"$in": ["Approved", "Posted"]},
            })
            if not linked_claim or claim_has_active_posted_transaction(db, linked_claim):
                return jsonify({"error": "Select an approved and unposted employee claim."}), 400
            amount, cgst_amount, cgst_percent, total_amount = claim_gst_breakdown(
                linked_claim.get("amount"),
                linked_claim.get("gst_percent"),
                linked_claim.get("gst_amount"),
                linked_claim.get("total_claim_amount"),
            )
            igst_percent = 0.0
            tds_percent = 0.0
            igst_amount = 0.0
            tds_amount = 0.0
            category = linked_claim.get("expense_category") or category
        loan_account_id = safe_int(data.get("loan_account_id"))
        loan_schedule_id = safe_int(data.get("loan_schedule_id"))
        linked_loan = None
        linked_schedule = None
        if category in {"Loan Disbursement", "Loan Repayment"}:
            if not loan_account_id:
                return jsonify({"error": "Loan Account Number is required for loan transactions."}), 400
            linked_loan = db.loan_accounts.find_one({"id": loan_account_id, "status": {"$ne": "Cancelled"}})
            if not linked_loan:
                return jsonify({"error": "Select a valid loan account."}), 400
            if category == "Loan Disbursement":
                if transaction_type != "Income":
                    return jsonify({"error": "Loan disbursement must be posted as an income/inflow transaction."}), 400
                totals = loan_totals(db, loan_account_id)
                if totals["total_disbursed_amount"] + total_amount > parse_float(linked_loan.get("total_loan_amount")) + 0.01:
                    return jsonify({"error": "Total disbursement cannot exceed approved loan amount."}), 400
            if category == "Loan Repayment":
                if transaction_type != "Expense":
                    return jsonify({"error": "Loan repayment must be posted as an expense/outflow transaction."}), 400
                if not loan_schedule_id:
                    return jsonify({"error": "Repayment schedule line is required for loan repayment."}), 400
                linked_schedule = db.loan_repayment_schedules.find_one({"id": loan_schedule_id, "loan_id": loan_account_id})
                if not linked_schedule:
                    return jsonify({"error": "Select a valid repayment schedule line for this loan."}), 400
            
        actor, actor_id, actor_name = audit_actor()
        insert_data = {
            "id": transaction_id,
            "account_id": account_id,
            "customer_id": customer_id,
            "vendor_id": int(data.get("vendor_id")) if data.get("vendor_id") else None,
            "project_id": int(data.get("project_id")) if data.get("project_id") else None,
            "invoice_id": invoice_id,
            "invoice_number": invoice_number,
            "loan_account_id": loan_account_id,
            "loan_schedule_id": loan_schedule_id,
            "expense_claim_id": expense_claim_id,
            "attachments": data.get("attachments") or [],
            "transaction_date": date_val,
            "date": date_val,
            "description": data.get("description"),
            "type": data.get("type", "Income"),
            "amount": amount,
            "currency": data.get("currency", "USD"),
            "reference": data.get("reference"),
            "category": category,
            "depreciation_value": float(data.get("depreciation_value") or 0) if category == "Fixed Assets" else None,
            "status": data.get("status", "Completed"),
            "cgst_percent": cgst_percent,
            "cgst_amount": cgst_amount,
            "igst_percent": igst_percent,
            "igst_amount": igst_amount,
            "tds_percent": tds_percent,
            "tds_amount": tds_amount,
            "total_amount": total_amount,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        merge_client_fields(insert_data, data)

        db.transactions.insert_one(insert_data)
        if category == "Loan Disbursement" and linked_loan:
            disb_id = get_next_sequence_value("loan_disbursements")
            db.loan_disbursements.insert_one({
                "id": disb_id,
                "loan_id": loan_account_id,
                "disbursement_date": date_val,
                "amount": total_amount,
                "bank_account_id": safe_int(data.get("bank_account_id") or linked_loan.get("bank_account_id")),
                "reference": data.get("reference"),
                "remarks": data.get("description"),
                "transaction_id": transaction_id,
                "status": "Posted",
                "created_at": datetime.now(),
            })
            db.loan_accounts.update_one({"id": loan_account_id}, {"$set": {"status": "Active", "updated_at": datetime.now()}})
            sync_transaction_to_treasury_revenue(db, insert_data)
        elif category == "Loan Repayment" and linked_schedule:
            final_status = "Paid" if total_amount >= parse_float(linked_schedule.get("total_amount")) else "Partially Paid"
            db.loan_repayment_schedules.update_one(
                {"id": loan_schedule_id},
                {"$set": {"status": final_status, "transaction_id": transaction_id, "paid_amount": total_amount, "updated_at": datetime.now()}},
            )
            sync_transaction_to_treasury_revenue(db, insert_data)
        elif linked_claim:
            db.expense_claims.update_one(
                {"id": expense_claim_id},
                {"$set": {
                    "status": "Posted",
                    "posted_transaction_id": transaction_id,
                    "posted_at": datetime.now(),
                    "posted_by": actor_id,
                    "updated_at": datetime.now(),
                }},
            )
            sync_transaction_to_treasury_revenue(db, insert_data)
        log_activity_async("Finance", "Accounting Entry", transaction_id, "CREATE", new_data=insert_data, reference_number=data.get("reference"))
        return jsonify({"id": transaction_id})
        
    transactions = list(db.transactions.aggregate([
        {"$lookup": {"from": "accounts", "localField": "account_id", "foreignField": "id", "as": "account"}},
        {"$unwind": {"path": "$account", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "vendors", "localField": "vendor_id", "foreignField": "id", "as": "vendor"}},
        {"$unwind": {"path": "$vendor", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "invoices", "localField": "invoice_id", "foreignField": "id", "as": "invoice"}},
        {"$unwind": {"path": "$invoice", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "account_name": "$account.name",
            "customer_name": "$customer.company_name",
            "vendor_name": "$vendor.name",
            "project_name": "$project.project_name",
            "invoice_number": {"$ifNull": ["$invoice.invoice_number", "$invoice_number"]},
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]}
        }},
        {"$project": {"account": 0, "customer": 0, "vendor": 0, "project": 0, "invoice": 0, "_id": 0}},
        {"$sort": {"transaction_date": -1, "created_at": -1, "id": -1}}
    ]))
    transaction_obj = db.custom_objects.find_one({"api_name": "transactions"})
    fields = get_fields_for_user(transaction_obj["id"]) if transaction_obj else []
    return jsonify(json_ready({"transactions": transactions, "fields": fields}))

@app.route("/api/finance/fixed-assets", methods=["GET"])
def api_finance_fixed_assets():
    require_finance_access()
    db = get_db()
    assets = list(db.transactions.aggregate([
        {"$match": {"category": "Fixed Assets", "status": {"$ne": "Reversed"}}},
        {"$lookup": {"from": "accounts", "localField": "account_id", "foreignField": "id", "as": "account"}},
        {"$unwind": {"path": "$account", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "vendors", "localField": "vendor_id", "foreignField": "id", "as": "vendor"}},
        {"$unwind": {"path": "$vendor", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "account_name": "$account.name",
            "vendor_name": "$vendor.name",
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]}
        }},
        {"$project": {"account": 0, "vendor": 0, "_id": 0}},
        {"$sort": {"transaction_date": -1}}
    ]))
    total_cost = sum(float(a.get("amount") or 0) for a in assets)
    total_current_value = sum(float(a.get("depreciation_value") or a.get("amount") or 0) for a in assets)
    return jsonify(json_ready({
        "assets": assets,
        "total_cost": total_cost,
        "total_current_value": total_current_value
    }))

@app.route("/api/finance/transactions/<transaction_id>", methods=["GET", "PUT", "DELETE"])
def api_finance_transaction_detail(transaction_id):
    require_finance_access()
    db = get_db()
    
    if request.method == "DELETE":
        old_tx = db.transactions.find_one({"id": transaction_id})
        if not old_tx:
            abort(404)

        db.transactions.delete_one({"id": transaction_id})

        synced_revenues = list(
            db.treasury_revenue.find(
                {"transaction_id": transaction_id, "is_settled": {"$ne": True}},
                {"id": 1, "revenue_id": 1, "_id": 0},
            )
        )
        synced_revenue_ids = [rev["id"] for rev in synced_revenues]
        if synced_revenue_ids:
            db.treasury_revenue.delete_many({"id": {"$in": synced_revenue_ids}})
            db.treasury_payouts.delete_many({"revenue_id": {"$in": synced_revenue_ids}})
            actor = get_current_user()
            if actor:
                refs = ", ".join(rev.get("revenue_id") or f"REV-{rev['id']}" for rev in synced_revenues)
                log_treasury_action(
                    actor["id"],
                    "Removed Unsettled Revenue",
                    f"Deleted transaction {transaction_id}; removed linked unsettled treasury revenue {refs}.",
                )

        log_activity_async(
            "Finance",
            "Accounting Entry",
            transaction_id,
            "DELETE",
            old_data=old_tx,
            reference_number=old_tx.get("reference"),
        )
        return jsonify({"success": True})

    if request.method == "PUT":
        data = request.get_json()
        amount = float(data.get("amount") or 0)
        cgst_percent = float(data.get("cgst_percent") or 0)
        igst_percent = float(data.get("igst_percent") or 0)
        tds_percent = float(data.get("tds_percent") or 0)
        
        cgst_amount = amount * (cgst_percent / 100.0)
        igst_amount = amount * (igst_percent / 100.0)
        tds_amount = amount * (tds_percent / 100.0)
        
        total_amount = amount + cgst_amount + igst_amount - tds_amount
        
        date_val = data.get("transaction_date") or data.get("date")
        if not date_val:
            date_val = datetime.now().strftime("%Y-%m-%d")
            
        account_id = int(data.get("account_id")) if data.get("account_id") else None
        customer_id = int(data.get("customer_id")) if data.get("customer_id") else None
        selected_account = db.accounts.find_one({"id": account_id}) if account_id else None
        transaction_type = data.get("type")
        if account_id and not account_available_for_transaction(selected_account, transaction_type):
            return jsonify({"error": "Selected account is not available for this transaction type."}), 400
        invoice_id = int(data.get("invoice_id")) if data.get("invoice_id") else None
        invoice_number = data.get("invoice_number")
        needs_invoice = transaction_type == "Income" and selected_account and selected_account.get("name") == "Sales Revenue"
        if needs_invoice:
            if not customer_id:
                return jsonify({"error": "Customer is required for Sales Revenue receipts."}), 400
            if not invoice_id:
                return jsonify({"error": "Invoice number is required for Sales Revenue receipts."}), 400
            invoice = db.invoices.find_one({
                "id": invoice_id,
                "customer_id": customer_id,
                "status": {"$in": INVOICE_RECEIPT_STATUSES},
                "$or": [
                    {"account_id": account_id},
                    {"account_id": {"$exists": False}},
                    {"account_id": None},
                ],
            })
            if not invoice:
                return jsonify({"error": "Select an approved, partially paid, or paid invoice for this customer and account."}), 400
            invoice_number = invoice.get("invoice_number")
        else:
            invoice_id = None
            invoice_number = None

        category = data.get("category")
        expense_claim_id = safe_int(data.get("expense_claim_id"))
        is_employee_claim_account = (
            transaction_type == "Expense"
            and selected_account
            and (
                str(selected_account.get("gl_code") or "").strip() == "7010"
                or selected_account.get("name") == "Employee Claims"
            )
        )
        if is_employee_claim_account and not expense_claim_id:
            return jsonify({"error": "Select an approved employee claim before posting to GL 7010 - Employee Claims."}), 400
        loan_account_id = safe_int(data.get("loan_account_id"))
        loan_schedule_id = safe_int(data.get("loan_schedule_id"))
        if category in {"Loan Disbursement", "Loan Repayment"}:
            if not loan_account_id:
                return jsonify({"error": "Loan Account Number is required for loan transactions."}), 400
            linked_loan = db.loan_accounts.find_one({"id": loan_account_id, "status": {"$ne": "Cancelled"}})
            if not linked_loan:
                return jsonify({"error": "Select a valid loan account."}), 400
            if category == "Loan Disbursement" and transaction_type != "Income":
                return jsonify({"error": "Loan disbursement must be posted as an income/inflow transaction."}), 400
            if category == "Loan Repayment":
                if transaction_type != "Expense":
                    return jsonify({"error": "Loan repayment must be posted as an expense/outflow transaction."}), 400
                if not loan_schedule_id:
                    return jsonify({"error": "Repayment schedule line is required for loan repayment."}), 400
                linked_schedule = db.loan_repayment_schedules.find_one({"id": loan_schedule_id, "loan_id": loan_account_id})
                if not linked_schedule:
                    return jsonify({"error": "Select a valid repayment schedule line for this loan."}), 400

        old_tx = db.transactions.find_one({"id": transaction_id})
        db.transactions.update_one(
            {"id": transaction_id},
            {"$set": {
                "account_id": account_id,
                "customer_id": customer_id,
                "vendor_id": int(data.get("vendor_id")) if data.get("vendor_id") else None,
                "project_id": int(data.get("project_id")) if data.get("project_id") else None,
                "invoice_id": invoice_id,
                "invoice_number": invoice_number,
                "loan_account_id": loan_account_id,
                "loan_schedule_id": loan_schedule_id,
                "expense_claim_id": expense_claim_id,
                "attachments": data.get("attachments") or [],
                "transaction_date": date_val,
                "date": date_val,
                "description": data.get("description"),
                "type": data.get("type"),
                "amount": amount,
                "currency": data.get("currency"),
                "reference": data.get("reference"),
                "category": category,
                "status": data.get("status"),
                "cgst_percent": cgst_percent,
                "cgst_amount": cgst_amount,
                "igst_percent": igst_percent,
                "igst_amount": igst_amount,
                "tds_percent": tds_percent,
                "tds_amount": tds_amount,
                "total_amount": total_amount
            }}
        )
        transaction_obj = db.custom_objects.find_one({"api_name": "transactions"})
        transaction_fields = get_fields_for_user(transaction_obj["id"]) if transaction_obj else []
        native_field_names = {field["api_name"] for field in transaction_fields if field.get("is_native")}
        dynamic_update_data = {
            k: v
            for k, v in data.items()
            if k not in native_field_names and k not in {"id", "created_at", "updated_at"}
        }
        if dynamic_update_data:
            db.transactions.update_one({"id": transaction_id}, {"$set": dynamic_update_data})
        new_tx = db.transactions.find_one({"id": transaction_id})
        if category == "Loan Repayment" and loan_schedule_id:
            linked_schedule = db.loan_repayment_schedules.find_one({"id": loan_schedule_id, "loan_id": loan_account_id})
            if linked_schedule:
                final_status = "Paid" if total_amount >= parse_float(linked_schedule.get("total_amount")) else "Partially Paid"
                db.loan_repayment_schedules.update_one(
                    {"id": loan_schedule_id},
                    {"$set": {"status": final_status, "transaction_id": transaction_id, "paid_amount": total_amount, "updated_at": datetime.now()}},
                )
        if category in {"Loan Disbursement", "Loan Repayment"} or db.treasury_revenue.find_one({"transaction_id": transaction_id}):
            sync_transaction_to_treasury_revenue(db, new_tx)
        log_activity_async("Finance", "Accounting Entry", transaction_id, "UPDATE", old_data=old_tx, new_data=new_tx, reference_number=new_tx.get("reference"))
        return jsonify({"success": True})
        
    transactions = list(db.transactions.aggregate([
        {"$match": {"id": transaction_id}},
        {"$lookup": {"from": "accounts", "localField": "account_id", "foreignField": "id", "as": "account"}},
        {"$unwind": {"path": "$account", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "vendors", "localField": "vendor_id", "foreignField": "id", "as": "vendor"}},
        {"$unwind": {"path": "$vendor", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "invoices", "localField": "invoice_id", "foreignField": "id", "as": "invoice"}},
        {"$unwind": {"path": "$invoice", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "account_name": "$account.name",
            "customer_name": "$customer.company_name",
            "vendor_name": "$vendor.name",
            "project_name": "$project.project_name",
            "invoice_number": {"$ifNull": ["$invoice.invoice_number", "$invoice_number"]},
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]}
        }},
        {"$project": {"account": 0, "customer": 0, "vendor": 0, "project": 0, "invoice": 0, "_id": 0}}
    ]))
    if not transactions:
        abort(404)
        
    transaction_obj = db.custom_objects.find_one({"api_name": "transactions"})
    fields = get_fields_for_user(transaction_obj["id"]) if transaction_obj else []

    return jsonify(json_ready({
        "transaction": transactions[0],
        "fields": fields,
        "currency_symbols": CURRENCY_SYMBOLS
    }))

@app.route("/api/finance/transactions/<transaction_id>/reverse", methods=["POST"])
def api_finance_transaction_reverse(transaction_id):
    require_finance_access()
    db = get_db()
    
    # 1. Update transaction status in db.transactions
    old_tx = db.transactions.find_one({"id": transaction_id})
    res = db.transactions.update_one(
        {"id": transaction_id},
        {"$set": {"status": "Reversed"}}
    )
    new_tx = db.transactions.find_one({"id": transaction_id})
    log_activity_async("Finance", "Accounting Entry", transaction_id, "UPDATE", old_data=old_tx, new_data=new_tx, reference_number=new_tx.get("reference") if new_tx else None)
    if res.matched_count == 0:
        abort(404)
    release_claim_posting_if_reversed(db, old_tx)
        
    # 2. Find and delete synced treasury revenue and its payouts immediately
    rev = db.treasury_revenue.find_one({"transaction_id": transaction_id})
    if rev:
        reverse_payables_for_revenue(db, rev, transaction_id)
        db.treasury_revenue.delete_many({"transaction_id": transaction_id})
        db.treasury_payouts.delete_many({"revenue_id": rev["id"]})
        
    # 3. Log administrative action
    user = get_current_user()
    log_treasury_action(user["id"], "Reverse Entry", f"Reversed transaction ledger entry #{transaction_id} and cancelled synced treasury splits.")
    
    return jsonify({"success": True})

def build_invoice_payment_details(bank_doc, invoice_number):
    if not bank_doc:
        return None
    return {
        "label": bank_doc.get("label"),
        "beneficiary_name": bank_doc.get("beneficiary_name", ""),
        "bank_name": bank_doc.get("bank_name", ""),
        "account_number": bank_doc.get("account_number", ""),
        "ifsc_code": bank_doc.get("ifsc_code", ""),
        "payment_reference": invoice_number or "",
    }


def snapshot_invoice_payment_details(db, bank_account_id, invoice_number):
    if not bank_account_id:
        return None
    bank = db.bank_accounts.find_one({"id": int(bank_account_id)}, {"_id": 0})
    return build_invoice_payment_details(bank, invoice_number)


def attach_invoice_payment_details(inv_dict, db):
    snap = inv_dict.get("payment_details_snapshot")
    if snap:
        details = dict(snap)
        details["payment_reference"] = inv_dict.get("invoice_number") or details.get("payment_reference", "")
        inv_dict["payment_details"] = details
        return
    bank_id = inv_dict.get("bank_account_id")
    if bank_id:
        bank = db.bank_accounts.find_one({"id": int(bank_id)}, {"_id": 0})
        inv_dict["payment_details"] = build_invoice_payment_details(bank, inv_dict.get("invoice_number"))
    else:
        inv_dict["payment_details"] = None


@app.route("/api/finance/invoices", methods=["GET", "POST"])
def api_invoices():
    require_finance_access()
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        invoice_id = get_next_sequence_value("invoices")
        
        # 1. Auto-generate invoice number format: SC + current year + current month + 3 digit sequence
        invoice_number = data.get("invoice_number")
        if not invoice_number:
            now = datetime.now()
            prefix = f"SC{now.strftime('%Y%m')}"
            import re
            month_invoices = list(db.invoices.find({"invoice_number": {"$regex": rf"^{prefix}\d{{3}}$"}}))
            if month_invoices:
                seqs = []
                for inv in month_invoices:
                    num_str = inv["invoice_number"]
                    try:
                        seqs.append(int(num_str[-3:]))
                    except ValueError:
                        pass
                next_seq = max(seqs) + 1 if seqs else 1
            else:
                next_seq = 1
            invoice_number = f"{prefix}{next_seq:03d}"
            
        # 2. Support frontend invoice_date and auto-populate issue_date
        issue_date = data.get("invoice_date") or data.get("issue_date")
        if not issue_date:
            issue_date = datetime.now().strftime("%Y-%m-%d")
            
        actor, actor_id, actor_name = audit_actor()
        total_amount = float(data.get("total_amount", 0))
        status = data.get("status", "Draft")
        amount_paid = normalize_invoice_amount_paid(status, data.get("amount_paid"), total_amount)
        insert_data = {
            "id": invoice_id,
            "invoice_number": invoice_number,
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "project_id": int(data.get("project_id")) if data.get("project_id") else None,
            "account_id": int(data.get("account_id")) if data.get("account_id") else None,
            "issue_date": issue_date,
            "due_date": data.get("due_date"),
            "subtotal": float(data.get("subtotal", 0)),
            "tax_rate": float(data.get("tax_rate", 0)),
            "tax_amount": float(data.get("tax_amount", 0)),
            "total_amount": total_amount,
            "currency": data.get("currency", "USD"),
            "status": status,
            "amount_paid": amount_paid,
            "notes": data.get("notes"),
            "items": data.get("items", []),
            "bank_account_id": int(data["bank_account_id"]) if data.get("bank_account_id") else None,
            "payment_details_snapshot": snapshot_invoice_payment_details(
                db, data.get("bank_account_id"), invoice_number
            ),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        db.invoices.insert_one(insert_data)
        log_activity_async("Finance", "Invoice", invoice_id, "CREATE", new_data=insert_data, reference_number=invoice_number)
        return jsonify({"id": invoice_id})
        
    invoices = list(db.invoices.aggregate([
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "customer_name": "$customer.company_name",
            "contact_name": "$customer.contact_name",
            "customer_email": "$customer.email",
            "customer_phone": "$customer.phone",
            "billing_address": "$customer.billing_address",
            "project_name": "$project.project_name"
        }},
        {"$project": {"customer": 0, "project": 0, "_id": 0}},
        {"$sort": {"issue_date": -1}}
    ]))
    for inv in invoices:
        inv["invoice_date"] = inv.get("issue_date")
        attach_invoice_payment_details(inv, db)
    return jsonify(json_ready({"invoices": invoices}))

@app.route("/api/finance/invoices/<int:invoice_id>", methods=["GET", "PUT", "DELETE"])
def api_invoice_detail(invoice_id):
    require_finance_access()
    db = get_db()
    
    if request.method == "PUT":
        data = request.get_json()
        actor, actor_id, actor_name = audit_actor()
        issue_date = data.get("invoice_date") or data.get("issue_date")
        if not issue_date:
            issue_date = datetime.now().strftime("%Y-%m-%d")
            
        old_inv = db.invoices.find_one({"id": invoice_id})
        if not old_inv:
            abort(404)
        status = data.get("status")
        if old_inv.get("status") in APPROVED_INVOICE_STATUSES:
            if status not in POST_APPROVAL_INVOICE_STATUSES:
                return jsonify({"error": "Approved invoices cannot be moved back to draft or sent status. Void this invoice and create a new one if correction is required."}), 400
            if invoice_core_changed(old_inv, data):
                return jsonify({"error": "Approved invoices cannot be edited. Void this invoice and create a new one if correction is required."}), 400
        inv_number = data.get("invoice_number") or (old_inv.get("invoice_number") if old_inv else None)
        bank_account_id = int(data["bank_account_id"]) if data.get("bank_account_id") else None
        total_amount = float(data.get("total_amount")) if data.get("total_amount") is not None else 0.0
        amount_paid = normalize_invoice_amount_paid(status, data.get("amount_paid"), total_amount)
        db.invoices.update_one(
            {"id": invoice_id},
            {"$set": {
                "invoice_number": data.get("invoice_number"),
                "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
                "project_id": int(data.get("project_id")) if data.get("project_id") else None,
                "account_id": int(data.get("account_id")) if data.get("account_id") else None,
                "issue_date": issue_date,
                "due_date": data.get("due_date"),
                "subtotal": float(data.get("subtotal")) if data.get("subtotal") is not None else 0.0,
                "tax_rate": float(data.get("tax_rate")) if data.get("tax_rate") is not None else 0.0,
                "tax_amount": float(data.get("tax_amount")) if data.get("tax_amount") is not None else 0.0,
                "total_amount": total_amount,
                "currency": data.get("currency"),
                "status": status,
                "amount_paid": amount_paid,
                "notes": data.get("notes"),
                "items": data.get("items", []),
                "bank_account_id": bank_account_id,
                "payment_details_snapshot": snapshot_invoice_payment_details(db, bank_account_id, inv_number),
                "updated_at": datetime.now(),
                "modified_by_id": actor_id,
                "modified_by_name": actor_name
            }}
        )
        new_inv = db.invoices.find_one({"id": invoice_id})
        log_activity_async("Finance", "Invoice", invoice_id, "UPDATE", old_data=old_inv, new_data=new_inv, reference_number=new_inv.get("invoice_number") if new_inv else None)
        return jsonify({"success": True})
        
    if request.method == "DELETE":
        old_inv = db.invoices.find_one({"id": invoice_id})
        db.invoices.delete_one({"id": invoice_id})
        log_activity_async("Finance", "Invoice", invoice_id, "DELETE", old_data=old_inv, reference_number=old_inv.get("invoice_number") if old_inv else None)
        return jsonify({"success": True})
        
    invoice = list(db.invoices.aggregate([
        {"$match": {"id": invoice_id}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "customer_name": "$customer.company_name",
            "contact_name": "$customer.contact_name",
            "customer_email": "$customer.email",
            "customer_phone": "$customer.phone",
            "billing_address": "$customer.billing_address",
            "project_name": "$project.project_name"
        }},
        {"$project": {"customer": 0, "project": 0, "_id": 0}}
    ]))
    if not invoice:
        abort(404)
        
    inv_dict = invoice[0]
    inv_dict["invoice_date"] = inv_dict.get("issue_date")
    
    # Load and embed company profile information
    setting = db.system_settings.find_one({"key_name": "company_profile"})
    company_info = json.loads(setting["value"]) if setting and setting.get("value") else None
    inv_dict["company_info"] = company_info
    attach_invoice_payment_details(inv_dict, db)
    
    return jsonify(json_ready({"invoice": inv_dict, "items": inv_dict.get("items", [])}))

@app.route("/api/settings/bank-accounts", methods=["GET", "POST"])
def api_settings_bank_accounts():
    db = get_db()
    if request.method == "POST":
        data = request.get_json() or {}
        bank_id = get_next_sequence_value("bank_accounts")
        is_default = bool(data.get("is_default"))
        if is_default:
            db.bank_accounts.update_many({}, {"$set": {"is_default": 0}})
        doc = {
            "id": bank_id,
            "label": (data.get("label") or "").strip(),
            "beneficiary_name": (data.get("beneficiary_name") or "").strip(),
            "bank_name": (data.get("bank_name") or "").strip(),
            "account_number": (data.get("account_number") or "").strip(),
            "ifsc_code": (data.get("ifsc_code") or "").strip(),
            "is_default": 1 if is_default else 0,
            "is_active": 0 if data.get("is_active") is False else 1,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
        }
        db.bank_accounts.insert_one(doc)
        log_activity_async("Setup", "Bank Account", bank_id, "CREATE", new_data=doc, reference_number=doc.get("label"))
        return jsonify(json_ready({"id": bank_id}))
    accounts = list(db.bank_accounts.find({}, {"_id": 0}).sort([("is_default", -1), ("label", 1)]))
    return jsonify(json_ready({"bank_accounts": accounts}))


@app.route("/api/settings/bank-accounts/<int:bank_id>", methods=["PUT", "DELETE"])
def api_settings_bank_account_detail(bank_id):
    db = get_db()
    existing = db.bank_accounts.find_one({"id": bank_id})
    if not existing:
        abort(404)
    if request.method == "DELETE":
        db.bank_accounts.delete_one({"id": bank_id})
        log_activity_async("Setup", "Bank Account", bank_id, "DELETE", old_data=existing, reference_number=existing.get("label"))
        return jsonify({"success": True})
    data = request.get_json() or {}
    is_default = bool(data.get("is_default")) if "is_default" in data else bool(existing.get("is_default"))
    if is_default:
        db.bank_accounts.update_many({"id": {"$ne": bank_id}}, {"$set": {"is_default": 0}})
    db.bank_accounts.update_one(
        {"id": bank_id},
        {
            "$set": {
                "label": (data.get("label", existing.get("label")) or "").strip(),
                "beneficiary_name": (data.get("beneficiary_name", existing.get("beneficiary_name")) or "").strip(),
                "bank_name": (data.get("bank_name", existing.get("bank_name")) or "").strip(),
                "account_number": (data.get("account_number", existing.get("account_number")) or "").strip(),
                "ifsc_code": (data.get("ifsc_code", existing.get("ifsc_code")) or "").strip(),
                "is_default": 1 if is_default else 0,
                "is_active": 0 if data.get("is_active") is False else 1,
                "updated_at": datetime.now(),
            }
        },
    )
    updated = db.bank_accounts.find_one({"id": bank_id})
    log_activity_async("Setup", "Bank Account", bank_id, "UPDATE", old_data=existing, new_data=updated, reference_number=updated.get("label") if updated else existing.get("label"))
    return jsonify({"success": True})


@app.route("/api/settings/company", methods=["GET", "POST"])
def api_settings_company():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        db.system_settings.update_one(
            {"key_name": "company_profile"},
            {"$set": {"value": json.dumps(data)}},
            upsert=True
        )
        return jsonify({"success": True})
        
    setting = db.system_settings.find_one({"key_name": "company_profile"})
    if setting and setting.get("value"):
        return jsonify(json_ready(json.loads(setting["value"])))
    return jsonify(json_ready({}))


@app.route("/api/settings/master-options/<option_type>", methods=["GET", "POST"])
def api_settings_master_options(option_type):
    require_finance_access()
    config = MASTER_OPTION_CONFIG.get(option_type)
    if not config:
        abort(404)
    db = get_db()
    ensure_master_options(db, config)
    collection = db[config["collection"]]

    if request.method == "POST":
        data = request.get_json() or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": f"{config['label']} name is required."}), 400
        if collection.find_one({"name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}}):
            return jsonify({"error": f"{config['label']} already exists."}), 400
        option_id = get_next_sequence_value(config["counter"])
        doc = {
            "id": option_id,
            "name": name,
            "is_active": 0 if data.get("is_active") is False else 1,
            "is_default": 0,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
        }
        collection.insert_one(doc)
        log_activity_async("Setup", config["label"], option_id, "CREATE", new_data=doc, reference_number=name)
        return jsonify(json_ready({"option": {k: v for k, v in doc.items() if k != "_id"}}))

    options = list(collection.find({}, {"_id": 0}).sort([("is_active", -1), ("name", 1)]))
    return jsonify(json_ready({config["response_key"]: options}))


@app.route("/api/settings/master-options/<option_type>/<int:option_id>", methods=["PUT"])
def api_settings_master_option_detail(option_type, option_id):
    require_finance_access()
    config = MASTER_OPTION_CONFIG.get(option_type)
    if not config:
        abort(404)
    db = get_db()
    ensure_master_options(db, config)
    collection = db[config["collection"]]
    existing = collection.find_one({"id": option_id})
    if not existing:
        abort(404)

    data = request.get_json() or {}
    name = (data.get("name", existing.get("name")) or "").strip()
    if not name:
        return jsonify({"error": f"{config['label']} name is required."}), 400
    duplicate = collection.find_one({
        "id": {"$ne": option_id},
        "name": {"$regex": f"^{re.escape(name)}$", "$options": "i"},
    })
    if duplicate:
        return jsonify({"error": f"{config['label']} already exists."}), 400

    update_data = {
        "name": name,
        "is_active": 0 if data.get("is_active") is False else 1,
        "updated_at": datetime.now(),
    }
    collection.update_one({"id": option_id}, {"$set": update_data})
    updated = collection.find_one({"id": option_id})
    log_activity_async("Setup", config["label"], option_id, "UPDATE", old_data=existing, new_data=updated, reference_number=name)
    return jsonify({"success": True})

def convert_to_usd(amount, currency, date_str, inr_rate, setting):
    amount = float(amount or 0.0)
    if not currency or currency == "USD":
        return amount
    
    # Determine the rate for the transaction date (monthly override support)
    month = date_str[:7] if date_str and len(date_str) >= 7 else ""
    current_rate = inr_rate
    if month and setting and setting.get("value"):
        try:
            rates_data = json.loads(setting["value"])
            monthly_rates = rates_data.get("INR", {}).get("monthly", {})
            if month in monthly_rates:
                current_rate = monthly_rates[month]
        except Exception:
            pass
            
    if currency == "INR":
        return amount / current_rate
    else:
        # Fallback for EUR/GBP
        return amount / current_rate


@app.route("/api/finance/reports/general-ledger")
def api_gl_report():
    require_finance_access()
    db = get_db()
    
    account_id = request.args.get("account_id")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    
    # Load exchange rates
    inr_rate = 95.0
    setting = db.system_settings.find_one({"key_name": "exchange_rates"})
    if setting and setting.get("value"):
        try:
            rates_data = json.loads(setting["value"])
            inr_rate = rates_data.get("INR", {}).get("default", 95.0)
        except Exception:
            pass

    # 1. Compute opening balance of previous transactions (normalized to USD)
    opening_balance = 0.0
    if start_date:
        opening_query = {"date": {"$lt": start_date}, "status": {"$ne": "Reversed"}}
        if account_id:
            opening_query["account_id"] = int(account_id)
            
        opening_txns = list(db.transactions.find(opening_query))
        for t in opening_txns:
            amt = float(t.get("total_amount") or t.get("amount") or 0.0)
            currency = t.get("currency", "USD")
            txn_date = t.get("transaction_date") or t.get("date")
            amt_usd = convert_to_usd(amt, currency, txn_date, inr_rate, setting)
            
            if t.get("type") == "Income":
                opening_balance += amt_usd
            else:
                opening_balance -= amt_usd
                
    # 2. Fetch period transactions
    period_query = {"status": {"$ne": "Reversed"}}
    if account_id:
        period_query["account_id"] = int(account_id)
    if start_date and end_date:
        period_query["date"] = {"$gte": start_date, "$lte": end_date}
    elif start_date:
        period_query["date"] = {"$gte": start_date}
    elif end_date:
        period_query["date"] = {"$lte": end_date}
        
    transactions = list(db.transactions.aggregate([
        {"$match": period_query},
        {"$lookup": {"from": "accounts", "localField": "account_id", "foreignField": "id", "as": "account"}},
        {"$unwind": {"path": "$account", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "vendors", "localField": "vendor_id", "foreignField": "id", "as": "vendor"}},
        {"$unwind": {"path": "$vendor", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "account_name": "$account.name",
            "customer_name": "$customer.company_name",
            "vendor_name": "$vendor.name",
            "project_name": "$project.project_name",
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]}
        }},
        {"$project": {"account": 0, "customer": 0, "vendor": 0, "project": 0, "_id": 0}},
        {"$sort": {"transaction_date": 1}}
    ]))
    
    # 3. Calculate running balance and debit/credit columns (normalized to USD)
    entries = []
    running_balance = opening_balance
    total_credits = 0.0
    total_debits = 0.0
    
    for t in transactions:
        amt = float(t.get("total_amount") or t.get("amount") or 0.0)
        currency = t.get("currency", "USD")
        txn_date = t.get("transaction_date") or t.get("date")
        amt_usd = convert_to_usd(amt, currency, txn_date, inr_rate, setting)
        
        is_income = t.get("type") == "Income"
        
        debit = None
        credit = None
        
        if is_income:
            credit = amt
            total_credits += amt_usd
            running_balance += amt_usd
        else:
            debit = amt
            total_debits += amt_usd
            running_balance -= amt_usd
            
        t["debit"] = debit
        t["credit"] = credit
        t["running_balance"] = running_balance
        entries.append(t)
        
    closing_balance = running_balance
    
    return jsonify(json_ready({
        "opening_balance": opening_balance,
        "total_credits": total_credits,
        "total_debits": total_debits,
        "closing_balance": closing_balance,
        "entries": entries
    }))

@app.route("/api/settings/currencies", methods=["GET", "POST"])
def api_settings_currencies():
    # Keep hardcoded array
    return jsonify(json_ready({"currencies": list(CURRENCY_SYMBOLS.keys()), "symbols": CURRENCY_SYMBOLS}))

@app.route("/api/settings/exchange-rates", methods=["GET", "POST"])
def api_settings_exchange_rates():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
        db.system_settings.update_one(
            {"key_name": "exchange_rates"},
            {"$set": {"value": json.dumps(data)}},
            upsert=True
        )
        return jsonify({"success": True})
        
    setting = db.system_settings.find_one({"key_name": "exchange_rates"})
    if setting and setting.get("value"):
        return jsonify(json_ready(json.loads(setting["value"])))
        
    return jsonify({
        "INR": {
            "default": 95.0,
            "monthly": {}
        }
    })

@app.route("/api/treasury/dashboard", methods=["GET"])
def api_treasury_dashboard():
    user = require_treasury_access()
    db = get_db()
    purge_orphaned_unsettled_transaction_revenue(db)
    purge_unsettled_revenue_payouts(db)
    normalize_stakeholder_flow_payouts(db)
    
    # 1. Reserve Fund — only settled revenue allocations (+ manual reserve expenses)
    settled_revenue_ids = get_settled_revenue_ids(db)
    reserve_balance_match = reserve_balance_payout_clause(settled_revenue_ids)

    reserve_acc_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Reserve Fund", **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    reserve_accumulated = reserve_acc_doc[0]["total"] if reserve_acc_doc else 0.0

    reserve_spent_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": {"$in": ["Reserve Expense", "Stakeholder Payout", "Channel Partner Payout"]}, **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    reserve_spent = reserve_spent_doc[0]["total"] if reserve_spent_doc else 0.0

    reserve_available = reserve_accumulated - reserve_spent

    # 2. Shared revenue = owner earnings + channel partner payouts (settled only; not contributions)
    shared_revenue_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": {"$in": ["Stakeholder", "Channel Partner"]}, **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]))
    shared_revenue = shared_revenue_doc[0]["total"] if shared_revenue_doc else 0.0
    
    # 3. Partner Payouts (settled revenue only)
    partner_paid_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Channel Partner", "status": "Paid", **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    partner_paid = partner_paid_doc[0]["total"] if partner_paid_doc else 0.0
    
    partner_pending_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Channel Partner", "status": "Pending", **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    partner_pending = partner_pending_doc[0]["total"] if partner_pending_doc else 0.0
    
    # 4. Stakeholder Payouts (settled revenue only)
    stakeholder_paid_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Stakeholder", "status": "Paid", **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    stakeholder_paid = stakeholder_paid_doc[0]["total"] if stakeholder_paid_doc else 0.0
    
    stakeholder_pending_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Stakeholder", "status": "Pending", **reserve_balance_match}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    stakeholder_pending = stakeholder_pending_doc[0]["total"] if stakeholder_pending_doc else 0.0
    
    # 5. Recent Payouts (settled revenue + manual reserve expenses)
    recent_payouts = list(db.treasury_payouts.aggregate([
        {"$match": reserve_balance_match},
        {"$lookup": {"from": "treasury_stakeholders", "localField": "stakeholder_id", "foreignField": "id", "as": "stk"}},
        {"$unwind": {"path": "$stk", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "treasury_partners", "localField": "partner_id", "foreignField": "id", "as": "part"}},
        {"$unwind": {"path": "$part", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "stakeholder_name": "$stk.name",
            "partner_name": "$part.name"
        }},
        {"$project": {"stk": 0, "part": 0, "_id": 0}},
        {"$sort": {"created_at": -1}},
        {"$limit": 5}
    ]))
    
    return jsonify(json_ready({
        "shared_revenue": shared_revenue,
        "reserve_accumulated": reserve_accumulated,
        "reserve_spent": reserve_spent,
        "reserve_available": reserve_available,
        "partner_paid": partner_paid,
        "partner_pending": partner_pending,
        "stakeholder_paid": stakeholder_paid,
        "stakeholder_pending": stakeholder_pending,
        "recent_payouts": recent_payouts
    }))

@app.route("/api/treasury/payment-stats", methods=["GET"])
def api_treasury_payment_stats():
    user = require_treasury_access()
    db = get_db()
    purge_orphaned_unsettled_transaction_revenue(db)
    purge_unsettled_revenue_payouts(db)
    normalize_stakeholder_flow_payouts(db)
    settled_revenue_ids = get_settled_revenue_ids(db)
    reserve_balance_match = reserve_balance_payout_clause(settled_revenue_ids)
    
    # 1. Fetch Stakeholders and calculate their metrics
    stk_list = []
    stakeholders = list(db.treasury_stakeholders.find({}))
    for s in stakeholders:
        sid = s.get("id")
        earned_paid = 0.0
        earned_pending = 0.0
        contributed_amt = 0.0
        
        earned_paid_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Paid", **reserve_balance_match}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if earned_paid_doc:
            earned_paid = earned_paid_doc[0]["total"]
        
        earned_pending_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Pending", **reserve_balance_match}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if earned_pending_doc:
            earned_pending = earned_pending_doc[0]["total"]
        
        contrib_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Stakeholder Contribution", "stakeholder_id": sid, **reserve_balance_match}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if contrib_doc:
            contributed_amt = contrib_doc[0]["total"]
        
        stk_list.append({
            "id": sid,
            "name": s.get("name"),
            "payout_percentage": s.get("payout_percentage"),
            "is_active": s.get("is_active"),
            "paid_amount": earned_paid,
            "pending_amount": earned_pending,
            "contributed_amount": contributed_amt,
            "earned_from_company": earned_paid + earned_pending,
        })
        
    # 2. Fetch Channel Partners and calculate their metrics
    part_list = []
    partners = list(db.treasury_partners.find({}))
    for p in partners:
        pid = p.get("id")
        paid_amt = 0.0
        pending_amt = 0.0
        
        # Aggregate paid
        paid_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Channel Partner", "partner_id": pid, "status": "Paid", **reserve_balance_match}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if paid_doc: paid_amt = paid_doc[0]["total"]
        
        # Aggregate pending
        pending_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Channel Partner", "partner_id": pid, "status": "Pending", **reserve_balance_match}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if pending_doc: pending_amt = pending_doc[0]["total"]
        
        part_list.append({
            "id": pid,
            "name": p.get("name"),
            "commission_type": p.get("commission_type"),
            "commission_value": p.get("commission_value"),
            "is_active": p.get("is_active"),
            "paid_amount": paid_amt,
            "pending_amount": pending_amt
        })
        
    # 3. Reserve Ledger (settled allocations + manual reserve expenses only)
    reserve_ledger = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": {"$in": ["Reserve Fund", "Reserve Expense", "Stakeholder Payout", "Channel Partner Payout"]}, **reserve_balance_match}},
        {"$lookup": {"from": "treasury_revenue", "localField": "revenue_id", "foreignField": "id", "as": "rev"}},
        {"$unwind": {"path": "$rev", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "payout_date": {"$ifNull": ["$payout_date", "$rev.entry_date"]},
            "associated_revenue_id": {"$concat": ["REV-", {"$toString": "$revenue_id"}]},
            "notes": "$description"
        }},
        {"$project": {"rev": 0, "_id": 0}},
        {"$sort": {"created_at": -1}}
    ]))
    
    # Standardize associated_revenue_id to null if no revenue_id
    for r in reserve_ledger:
        if not r.get("revenue_id"):
            r["associated_revenue_id"] = None
            
    return jsonify(json_ready({
        "stakeholders": stk_list,
        "partners": part_list,
        "reserve_ledger": reserve_ledger
    }))


@app.route("/api/treasury/payables", methods=["GET"])
def api_treasury_payables():
    require_treasury_access()
    db = get_db()
    sync_negative_revenue_payables(db)
    sync_reversed_transaction_payables(db)
    sync_approved_payout_payables(db)
    status = request.args.get("status")
    query = {}
    if status:
        query["status"] = status
    payables = list(db.payables.find(query, {"_id": 0}).sort([("transaction_date", -1), ("created_at", -1)]))
    for payable in payables:
        latest_payment = db.payable_payments.find_one(
            {"payable_id": payable.get("id")},
            {"_id": 0},
            sort=[("created_at", -1), ("id", -1)],
        )
        if latest_payment:
            if not payable.get("last_payment_id"):
                payable["last_payment_id"] = latest_payment.get("id")
            if not payable.get("last_payment_reference"):
                payable["last_payment_reference"] = latest_payment.get("reference")
            if not payable.get("payment_reference"):
                payable["payment_reference"] = latest_payment.get("reference")
            if not payable.get("last_payment_date"):
                payable["last_payment_date"] = latest_payment.get("payment_date")
            if not payable.get("last_payment_amount"):
                payable["last_payment_amount"] = latest_payment.get("payment_amount")
            if not payable.get("last_payment_mode"):
                payable["last_payment_mode"] = latest_payment.get("payment_mode")
    stats = {
        "total_payables": sum(parse_float(p.get("original_amount")) for p in payables if p.get("status") not in {"Cancelled", "Reversed"}),
        "pending_payments": sum(parse_float(p.get("outstanding_amount")) for p in payables if p.get("status") in {"Pending", "Partially Paid"}),
        "paid_amount": sum(parse_float(p.get("paid_amount")) for p in payables),
        "company_fund_available": company_fund_available(db),
    }
    return jsonify(json_ready({"payables": payables, "stats": stats}))


@app.route("/api/treasury/payables/<int:payable_id>/payments", methods=["POST"])
def api_treasury_payable_payment(payable_id):
    user = require_treasury_access()
    db = get_db()
    payable = db.payables.find_one({"id": payable_id})
    if not payable:
        abort(404)
    if payable.get("status") in {"Paid", "Cancelled", "Reversed"}:
        return jsonify({"error": "This payable is already closed."}), 400
    data = request.get_json() or {}
    outstanding = parse_float(payable.get("outstanding_amount"), payable.get("original_amount"))
    payment_amount = parse_float(data.get("payment_amount"), outstanding)
    if payment_amount <= 0:
        return jsonify({"error": "Payment amount must be greater than zero."}), 400
    if payment_amount > outstanding + 0.01:
        return jsonify({"error": "Overpayment is not allowed."}), 400
    available = company_fund_available(db)
    if payment_amount > available + 0.01:
        return jsonify({"error": "Insufficient company fund for this payment."}), 400
    payment_id = get_next_sequence_value("payable_payments")
    payment_date = data.get("payment_date") or datetime.now().strftime("%Y-%m-%d")
    payment_reference = (data.get("reference") or "").strip()
    db.payable_payments.insert_one({
        "id": payment_id,
        "payable_id": payable_id,
        "payment_amount": payment_amount,
        "payment_date": payment_date,
        "bank_account_id": safe_int(data.get("bank_account_id")),
        "payment_mode": data.get("payment_mode"),
        "reference": payment_reference,
        "remarks": data.get("remarks"),
        "created_at": datetime.now(),
        "created_by_id": user["id"],
    })
    is_payout_payable = payable.get("source_module") in {"Stakeholder Payout", "Channel Partner Payout"}
    treasury_payout_type = payable.get("source_module") if is_payout_payable else "Reserve Expense"
    payout_source = db.stakeholder_payout_receipts.find_one({"id": payable.get("source_id")}) if is_payout_payable else None
    db.treasury_payouts.insert_one({
        "id": get_next_sequence_value("treasury_payouts"),
        "payable_id": payable_id,
        "payout_type": treasury_payout_type,
        "stakeholder_payout_id": payable.get("source_id") if is_payout_payable else None,
        "stakeholder_id": (payout_source or {}).get("stakeholder_id"),
        "stakeholder_name": (payout_source or {}).get("stakeholder_name"),
        "partner_id": (payout_source or {}).get("partner_id"),
        "partner_name": (payout_source or {}).get("partner_name"),
        "amount": payment_amount,
        "status": "Paid",
        "payout_date": payment_date,
        "reference": payment_reference,
        "description": f"Payable payment {payable.get('payable_number')} - {payable.get('source_reference')}",
        "created_at": datetime.now(),
        "created_by_id": user["id"],
    })
    paid_amount = parse_float(payable.get("paid_amount")) + payment_amount
    new_outstanding = max(0.0, parse_float(payable.get("original_amount")) - paid_amount)
    status = "Paid" if new_outstanding <= 0.01 else "Partially Paid"
    db.payables.update_one(
        {"id": payable_id},
        {"$set": {
            "paid_amount": paid_amount,
            "outstanding_amount": new_outstanding,
            "status": status,
            "payment_status": status,
            "payment_mode": data.get("payment_mode"),
            "settlement_account": safe_int(data.get("bank_account_id")),
            "last_payment_id": payment_id,
            "last_payment_reference": payment_reference,
            "payment_reference": payment_reference,
            "last_payment_date": payment_date,
            "last_payment_amount": payment_amount,
            "last_payment_mode": data.get("payment_mode"),
            "last_payment_remarks": data.get("remarks"),
            "updated_at": datetime.now(),
        }},
    )
    if is_payout_payable:
        payout = payout_source or db.stakeholder_payout_receipts.find_one({"id": payable.get("source_id")})
        payout_paid_amount = parse_float((payout or {}).get("paid_amount")) + payment_amount
        payout_outstanding = max(0.0, parse_float((payout or {}).get("amount")) - payout_paid_amount)
        payout_status = "Paid" if payout_outstanding <= 0.01 else "Partially Paid"
        db.stakeholder_payout_payments.insert_one({
            "id": get_next_sequence_value("stakeholder_payout_payments"),
            "payout_id": payable.get("source_id"),
            "payable_id": payable_id,
            "payment_amount": payment_amount,
            "payment_date": payment_date,
            "bank_account_id": safe_int(data.get("bank_account_id")),
            "payment_mode": data.get("payment_mode"),
            "reference": payment_reference,
            "remarks": data.get("remarks"),
            "created_at": datetime.now(),
            "created_by_id": user["id"],
        })
        db.stakeholder_payout_receipts.update_one(
            {"id": payable.get("source_id")},
            {"$set": {
                "paid_amount": payout_paid_amount,
                "outstanding_amount": payout_outstanding,
                "status": payout_status,
                "last_payment_id": payment_id,
                "last_payment_reference": payment_reference,
                "payment_reference": payment_reference,
                "last_payment_date": payment_date,
                "last_payment_amount": payment_amount,
                "last_payment_mode": data.get("payment_mode"),
                "payable_id": payable_id,
                "updated_at": datetime.now(),
            }},
        )
    log_treasury_action(user["id"], "Payable Paid", f"Paid {payment_amount:.2f} against {payable.get('payable_number')}.")
    return jsonify({"success": True, "status": status})


@app.route("/api/treasury/reserve/expense", methods=["POST"])
def api_treasury_reserve_expense():
    user = require_treasury_access()
    db = get_db()
    data = request.get_json() or {}
    
    amount = float(data.get("amount", 0))
    desc = data.get("description", "Reserve Expense")
    expense_date = data.get("expense_date", datetime.now().strftime("%Y-%m-%d"))
    
    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    payable_id = get_next_sequence_value("payables")
    db.payables.insert_one({
        "id": payable_id,
        "payable_number": f"PAY-{payable_id:05d}",
        "source_module": "Treasury Expense",
        "source_id": payable_id,
        "source_reference": f"TREXP-{payable_id:05d}",
        "party_name": "Treasury Expense",
        "transaction_date": expense_date,
        "original_amount": amount,
        "outstanding_amount": amount,
        "paid_amount": 0.0,
        "payment_status": "Pending",
        "status": "Pending",
        "remarks": desc,
        "created_at": datetime.now(),
        "updated_at": datetime.now(),
    })
    
    log_treasury_action(user["id"], "Treasury Payable Created", f"Created payable {payable_id} for reserve expense: {desc}")
    return jsonify({"ok": True, "payable_id": payable_id})

@app.route("/api/treasury/stakeholders/<int:sid>/settle", methods=["POST"])
def api_treasury_stakeholder_settle(sid):
    user = require_treasury_access()
    db = get_db()
    
    stk = db.treasury_stakeholders.find_one({"id": sid}, {"_id": 0, "name": 1})
    stk_name = stk.get("name") if stk else f"ID {sid}"
    
    pending_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Pending", **reserve_balance_payout_clause(get_settled_revenue_ids(db))}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}},
    ]))
    pending_total = pending_doc[0]["total"] if pending_doc else 0.0
    
    db.treasury_payouts.update_many(
        {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Pending"},
        {"$set": {"status": "Paid"}}
    )
    
    log_treasury_action(
        user["id"],
        "Owner Earnings Settled",
        f"Marked ₹{pending_total:.2f} pending earnings as Paid for {stk_name}.",
    )
    return jsonify({"ok": True})

@app.route("/api/treasury/partners/<int:pid>/settle", methods=["POST"])
def api_treasury_partner_settle(pid):
    user = require_treasury_access()
    db = get_db()
    
    db.treasury_payouts.update_many(
        {"payout_type": "Channel Partner", "partner_id": pid, "status": "Pending"},
        {"$set": {"status": "Paid"}}
    )
    
    log_treasury_action(user["id"], "Partner Settled", f"Partner ID {pid} pending commissions marked as Paid.")
    return jsonify({"ok": True})

@app.route("/api/treasury/stakeholders", methods=["GET", "POST"])
def api_treasury_stakeholders():
    user = require_treasury_access()
    db = get_db()
    
    if request.method == "POST":
        data = request.get_json() or {}
        sid = get_next_sequence_value("treasury_stakeholders")
        
        payout_pct = float(data.get("payout_percentage", 0))
        linked_user_id = safe_int(data.get("linked_user_id"))
        if linked_user_id and not db.app_users.find_one({"id": linked_user_id, "is_active": {"$ne": 0}}):
            return jsonify({"error": "Linked user account must be an active user."}), 400
        db.treasury_stakeholders.insert_one({
            "id": sid,
            "name": data.get("name"),
            "email": data.get("email"),
            "linked_user_id": linked_user_id,
            "approval_sequence": int(data.get("approval_sequence") or 0),
            "payout_percentage": payout_pct,
            "equity_percentage": payout_pct, # backward compatible
            "payment_details": data.get("payment_details", ""),
            "remarks": data.get("remarks", ""),
            "is_active": data.get("is_active", True),
            "created_at": datetime.now()
        })
        log_treasury_action(
            user["id"],
            "Added Company Owner",
            format_stakeholder_audit_details(None, data),
        )
        return jsonify({"ok": True})
        
    stakeholders = list(db.treasury_stakeholders.aggregate([
        {"$lookup": {"from": "app_users", "localField": "linked_user_id", "foreignField": "id", "as": "linked_user"}},
        {"$unwind": {"path": "$linked_user", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "linked_user_name": "$linked_user.full_name",
            "linked_user_email": "$linked_user.email",
        }},
        {"$project": {"_id": 0, "linked_user": 0}},
        {"$sort": {"approval_sequence": 1, "created_at": -1}},
    ]))
    return jsonify(json_ready({"stakeholders": stakeholders}))

@app.route("/api/treasury/stakeholders/<int:sid>", methods=["PUT"])
def api_treasury_stakeholder_detail(sid):
    user = require_treasury_access()
    db = get_db()
    data = request.get_json() or {}
    
    old_doc = db.treasury_stakeholders.find_one({"id": sid}, {"_id": 0})
    if not old_doc:
        return jsonify({"error": "Stakeholder not found."}), 404

    payout_pct = float(data.get("payout_percentage", 0))
    linked_user_id = safe_int(data.get("linked_user_id"))
    if linked_user_id and not db.app_users.find_one({"id": linked_user_id, "is_active": {"$ne": 0}}):
        return jsonify({"error": "Linked user account must be an active user."}), 400
    db.treasury_stakeholders.update_one(
        {"id": sid},
        {"$set": {
            "name": data.get("name"),
            "email": data.get("email"),
            "linked_user_id": linked_user_id,
            "approval_sequence": int(data.get("approval_sequence") or 0),
            "payout_percentage": payout_pct,
            "equity_percentage": payout_pct, # backward compatible
            "payment_details": data.get("payment_details", ""),
            "remarks": data.get("remarks", ""),
            "is_active": data.get("is_active", True)
        }}
    )
    log_treasury_action(
        user["id"],
        "Updated Company Owner",
        format_stakeholder_audit_details(old_doc, data),
    )
    return jsonify({"ok": True})


@app.route("/api/treasury/stakeholder-payouts", methods=["GET", "POST"])
def api_treasury_stakeholder_payouts():
    user = require_treasury_access()
    db = get_db()
    if request.method == "POST":
        data = request.get_json() or {}
        status = data.get("status", "Draft")
        if status not in {"Draft", "Submitted"}:
            return jsonify({"error": "Payout can only be created as Draft or Submitted."}), 400
        recipient, recipient_error = payout_recipient_payload(db, data)
        if recipient_error:
            return jsonify({"error": recipient_error}), 400
        payout_type = data.get("payout_type", "Profit Distribution")
        if payout_type not in STAKEHOLDER_PAYOUT_TYPES:
            return jsonify({"error": "Invalid payout type."}), 400
        amount = parse_float(data.get("amount"))
        if amount <= 0:
            return jsonify({"error": "Payout amount must be greater than zero."}), 400
        payout_id = get_next_sequence_value("stakeholder_payout_receipts")
        doc = {
            "id": payout_id,
            "payout_number": data.get("payout_number") or f"SP-{datetime.now().strftime('%Y%m')}-{payout_id:04d}",
            **recipient,
            "payout_date": data.get("payout_date") or datetime.now().strftime("%Y-%m-%d"),
            "payout_type": payout_type,
            "amount": amount,
            "paid_amount": 0.0,
            "outstanding_amount": amount,
            "payment_mode": data.get("payment_mode"),
            "bank_account_id": safe_int(data.get("bank_account_id")),
            "reference": data.get("reference"),
            "remarks": data.get("remarks"),
            "attachment": data.get("attachment"),
            "status": status,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": user["id"],
            "created_by_name": user.get("full_name"),
        }
        db.stakeholder_payout_receipts.insert_one(doc)
        if status == "Submitted":
            initialize_stakeholder_payout_approval_workflow(db, payout_id, user)
        log_treasury_action(user["id"], "Created Payout", f"Created payout {doc['payout_number']} for {recipient.get('recipient_name')}.")
        saved = db.stakeholder_payout_receipts.find_one({"id": payout_id}, {"_id": 0})
        attach_pending_approval_display(db, saved, "stakeholder_payout_approvals", "payout_id")
        return jsonify(json_ready({"payout": normalize_payout_recipient(saved)}))

    payouts = list(db.stakeholder_payout_receipts.find({}, {"_id": 0}).sort([("created_at", -1)]))
    payouts = [
        normalize_payout_recipient(attach_pending_approval_display(db, payout, "stakeholder_payout_approvals", "payout_id"))
        for payout in payouts
    ]
    return jsonify(json_ready({"payouts": payouts, "company_fund_available": company_fund_available(db)}))


@app.route("/api/treasury/stakeholder-payouts/<int:payout_id>", methods=["GET", "PUT"])
def api_treasury_stakeholder_payout_detail(payout_id):
    user = require_treasury_access()
    db = get_db()
    payout = db.stakeholder_payout_receipts.find_one({"id": payout_id}, {"_id": 0})
    if not payout:
        abort(404)
    if request.method == "PUT":
        if payout.get("status") != "Draft":
            return jsonify({"error": "Payout cannot be edited after submission."}), 400
        data = request.get_json() or {}
        recipient, recipient_error = payout_recipient_payload(db, data, payout)
        if recipient_error:
            return jsonify({"error": recipient_error}), 400
        amount = parse_float(data.get("amount"), payout.get("amount"))
        if amount <= 0:
            return jsonify({"error": "Payout amount must be greater than zero."}), 400
        status = data.get("status", payout.get("status"))
        update = {
            **recipient,
            "payout_date": data.get("payout_date", payout.get("payout_date")),
            "payout_type": data.get("payout_type", payout.get("payout_type")),
            "amount": amount,
            "outstanding_amount": amount,
            "payment_mode": data.get("payment_mode", payout.get("payment_mode")),
            "bank_account_id": safe_int(data.get("bank_account_id", payout.get("bank_account_id"))),
            "reference": data.get("reference", payout.get("reference")),
            "remarks": data.get("remarks", payout.get("remarks")),
            "attachment": data.get("attachment", payout.get("attachment")),
            "status": status,
            "updated_at": datetime.now(),
        }
        if update["payout_type"] not in STAKEHOLDER_PAYOUT_TYPES:
            return jsonify({"error": "Invalid payout type."}), 400
        db.stakeholder_payout_receipts.update_one({"id": payout_id}, {"$set": update})
        if status == "Submitted":
            initialize_stakeholder_payout_approval_workflow(db, payout_id, user)
        return jsonify({"success": True})
    payments = list(db.stakeholder_payout_payments.find({"payout_id": payout_id}, {"_id": 0}).sort("payment_date", -1))
    approvals = list(db.stakeholder_payout_approvals.find({"payout_id": payout_id}, {"_id": 0}).sort([("approval_sequence", 1), ("id", 1)]))
    attach_approval_user_names(db, approvals)
    attach_pending_approval_display(db, payout, "stakeholder_payout_approvals", "payout_id")
    return jsonify(json_ready({"payout": normalize_payout_recipient(payout), "payments": payments, "approvals": approvals}))


@app.route("/api/treasury/stakeholder-payouts/<int:payout_id>/action", methods=["POST"])
def api_treasury_stakeholder_payout_action(payout_id):
    user = require_treasury_access()
    db = get_db()
    payout = db.stakeholder_payout_receipts.find_one({"id": payout_id})
    if not payout:
        abort(404)
    data = request.get_json() or {}
    action = data.get("action")
    if action == "submit":
        if payout.get("status") != "Draft":
            return jsonify({"error": "Only draft payouts can be submitted."}), 400
        status = initialize_stakeholder_payout_approval_workflow(db, payout_id, user)
        return jsonify({"success": True, "status": status})
    if action == "cancel":
        if payout.get("status") != "Draft":
            return jsonify({"error": "Payout cannot be cancelled after submission."}), 400
        db.stakeholder_payout_receipts.update_one({"id": payout_id}, {"$set": {"status": "Cancelled", "updated_at": datetime.now()}})
        return jsonify({"success": True, "status": "Cancelled"})
    if action == "mark_paid":
        return jsonify({"error": "Approved payouts must be paid from Treasury Payables."}), 400
    return jsonify({"error": "Invalid payout action."}), 400


@app.route("/api/treasury/stakeholder-payout-approvals/pending", methods=["GET"])
def api_pending_stakeholder_payout_approvals():
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user = get_current_user()
    match = {"status": "Pending"}
    if not can_manage_payout_approvals(user, db):
        match["linked_user_id"] = session["user_id"]
    approvals = list(db.stakeholder_payout_approvals.aggregate([
        {"$match": match},
        {"$lookup": {"from": "stakeholder_payout_receipts", "localField": "payout_id", "foreignField": "id", "as": "payout"}},
        {"$unwind": "$payout"},
        {"$match": {"payout.status": {"$regex": "^Pending"}}},
        {"$project": {"_id": 0, "payout._id": 0}},
        {"$sort": {"approval_sequence": 1, "created_at": 1}},
    ]))
    for approval in approvals:
        attach_approval_user_names(db, [approval])
        normalize_payout_recipient(approval.get("payout"))
        attach_pending_approval_display(db, approval.get("payout"), "stakeholder_payout_approvals", "payout_id")
        approval["can_act"] = approval.get("linked_user_id") == user["id"]
    return jsonify(json_ready({"approvals": approvals}))


@app.route("/api/treasury/stakeholder-payout-approvals/<int:approval_id>/action", methods=["POST"])
def api_stakeholder_payout_approval_action(approval_id):
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user = get_current_user()
    data = request.get_json() or {}
    action = data.get("action")
    if action not in {"approve", "reject"}:
        return jsonify({"error": "Invalid approval action."}), 400
    approval = db.stakeholder_payout_approvals.find_one({"id": approval_id, "linked_user_id": user["id"]})
    if not approval or approval.get("status") != "Pending":
        return jsonify({"error": "Approval task not found for this user."}), 404
    payout = db.stakeholder_payout_receipts.find_one({"id": approval.get("payout_id")})
    if not payout or not str(payout.get("status", "")).startswith("Pending"):
        return jsonify({"error": "Payout is not pending approval."}), 400
    now = datetime.now()
    final_status = "Approved" if action == "approve" else "Rejected"
    db.stakeholder_payout_approvals.update_one(
        {"id": approval_id},
        {"$set": {"status": final_status, "remarks": data.get("remarks", ""), "action_at": now, "action_by_id": user["id"], "action_by_name": user.get("full_name")}},
    )
    db.stakeholder_payout_approval_audit.insert_one({
        "id": get_next_sequence_value("stakeholder_payout_approval_audit"),
        "payout_id": payout["id"],
        "approval_id": approval_id,
        "approval_sequence": approval.get("approval_sequence"),
        "action": final_status,
        "remarks": data.get("remarks", ""),
        "created_at": now,
        "created_by_id": user["id"],
    })
    if action == "reject":
        db.stakeholder_payout_approvals.update_many({"payout_id": payout["id"], "status": {"$in": ["Pending", "Waiting"]}}, {"$set": {"status": "Skipped", "updated_at": now}})
        db.stakeholder_payout_receipts.update_one({"id": payout["id"]}, {"$set": {"status": "Rejected", "rejected_at": now, "rejected_by_id": user["id"], "updated_at": now}})
        return jsonify({"success": True, "status": "Rejected"})
    if db.stakeholder_payout_approvals.count_documents({"payout_id": payout["id"], "approval_sequence": approval.get("approval_sequence"), "status": "Pending"}):
        status = pending_approval_status(db, "stakeholder_payout_approvals", "payout_id", payout["id"], approval.get("approval_sequence"))
        db.stakeholder_payout_receipts.update_one({"id": payout["id"]}, {"$set": {"status": status, "updated_at": now}})
        return jsonify({"success": True, "status": status})
    next_step = db.stakeholder_payout_approvals.find_one({"payout_id": payout["id"], "status": "Waiting"}, sort=[("approval_sequence", 1), ("id", 1)])
    if next_step:
        next_sequence = int(next_step.get("approval_sequence") or 999)
        db.stakeholder_payout_approvals.update_many({"payout_id": payout["id"], "approval_sequence": next_sequence, "status": "Waiting"}, {"$set": {"status": "Pending", "updated_at": now}})
        status = pending_approval_status(db, "stakeholder_payout_approvals", "payout_id", payout["id"], next_sequence)
        db.stakeholder_payout_receipts.update_one({"id": payout["id"]}, {"$set": {"status": status, "current_approval_sequence": next_sequence, "updated_at": now}})
        return jsonify({"success": True, "status": status})
    db.stakeholder_payout_receipts.update_one({"id": payout["id"]}, {"$set": {"status": "Approved", "approval_completed": True, "approved_at": now, "updated_at": now}})
    approved_payout = db.stakeholder_payout_receipts.find_one({"id": payout["id"]})
    create_or_update_payable_from_payout(db, approved_payout)
    return jsonify({"success": True, "status": "Pending Payment"})


@app.route("/api/treasury/channel-partners", methods=["GET", "POST"])
def api_treasury_partners():
    user = require_treasury_access()
    db = get_db()
    
    if request.method == "POST":
        data = request.get_json() or {}
        pid = get_next_sequence_value("treasury_partners")
        
        commission_val = float(data.get("commission_value", 0))
        db.treasury_partners.insert_one({
            "id": pid,
            "name": data.get("name"),
            "partner_name": data.get("name"), # backward compatible
            "commission_type": data.get("commission_type", "Percentage"),
            "commission_value": commission_val,
            "commission_rate": commission_val, # backward compatible
            "is_active": data.get("is_active", True),
            "created_at": datetime.now()
        })
        log_treasury_action(user["id"], "Added Partner", f"Created partner {data.get('name')}")
        return jsonify({"ok": True})
        
    partners = list(db.treasury_partners.find({}, {"_id": 0}))
    return jsonify(json_ready({"partners": partners}))

@app.route("/api/treasury/channel-partners/<int:pid>", methods=["PUT"])
def api_treasury_partner_detail(pid):
    user = require_treasury_access()
    db = get_db()
    data = request.get_json() or {}
    
    commission_val = float(data.get("commission_value", 0))
    db.treasury_partners.update_one(
        {"id": pid},
        {"$set": {
            "name": data.get("name"),
            "partner_name": data.get("name"), # backward compatible
            "commission_type": data.get("commission_type", "Percentage"),
            "commission_value": commission_val,
            "commission_rate": commission_val, # backward compatible
            "is_active": data.get("is_active", True)
        }}
    )
    log_treasury_action(user["id"], "Updated Partner", f"Updated partner ID {pid}")
    return jsonify({"ok": True})


@app.route("/api/finance/expense-claims", methods=["GET", "POST"])
def api_expense_claims():
    require_finance_access()
    db = get_db()
    if request.method == "POST":
        data = request.get_json() or {}
        status = data.get("status", "Draft")
        if status not in {"Draft", "Submitted"}:
            return jsonify({"error": "Claims can only be created as Draft or Submitted."}), 400
        amount = parse_float(data.get("amount"))
        gst_percent = parse_float(data.get("gst_percent"))
        gst_amount = parse_float(data.get("gst_amount"), amount * (gst_percent / 100.0))
        if gst_percent:
            gst_amount = round(amount * (gst_percent / 100.0), 2)
        total_claim_amount = parse_float(data.get("total_claim_amount"), amount + gst_amount)
        if total_claim_amount <= 0:
            return jsonify({"error": "Total claim amount must be greater than zero."}), 400
        claim_id = get_next_sequence_value("expense_claims")
        claim_number = data.get("claim_number") or f"CLM-{datetime.now().strftime('%Y%m')}-{claim_id:04d}"
        actor = require_current_user()
        doc = {
            "id": claim_id,
            "claim_number": claim_number,
            "employee_name": (data.get("employee_name") or "").strip(),
            "department": (data.get("department") or "").strip(),
            "claim_date": data.get("claim_date") or datetime.now().strftime("%Y-%m-%d"),
            "expense_date": data.get("expense_date") or data.get("claim_date") or datetime.now().strftime("%Y-%m-%d"),
            "expense_category": data.get("expense_category") or "Operating Expenses",
            "expense_description": data.get("expense_description") or data.get("description") or "",
            "amount": amount,
            "gst_percent": gst_percent,
            "gst_amount": gst_amount,
            "total_claim_amount": total_claim_amount,
            "payment_mode": data.get("payment_mode"),
            "attachment": data.get("attachment"),
            "remarks": data.get("remarks"),
            "status": status,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor["id"],
            "created_by_name": actor.get("full_name") or actor.get("email") or "Unknown User",
        }
        db.expense_claims.insert_one(doc)
        if status == "Submitted":
            initialize_claim_approval_workflow(db, claim_id, actor)
        log_activity_async("Finance", "Expense Claim", claim_id, "CREATE", new_data=doc, reference_number=claim_number)
        saved = db.expense_claims.find_one({"id": claim_id}, {"_id": 0})
        attach_pending_approval_display(db, saved, "claim_approvals", "claim_id")
        return jsonify(json_ready({"claim": saved}))

    status = request.args.get("status")
    query = {}
    if status:
        query["status"] = status
    claims = list(db.expense_claims.find(query, {"_id": 0}).sort([("claim_date", -1), ("created_at", -1)]))
    for claim in claims:
        attach_pending_approval_display(db, claim, "claim_approvals", "claim_id")
    return jsonify(json_ready({"claims": [claim_summary(claim) for claim in claims]}))


@app.route("/api/finance/expense-claims/approved-unposted", methods=["GET"])
def api_expense_claims_approved_unposted():
    require_finance_access()
    db = get_db()
    claims = list(db.expense_claims.find({
        "status": {"$in": ["Approved", "Posted"]},
    }, {"_id": 0}).sort([("approved_at", 1), ("claim_date", 1)]))
    claims = [claim for claim in claims if not claim_has_active_posted_transaction(db, claim)]
    return jsonify(json_ready({"claims": [claim_summary(claim) for claim in claims]}))


@app.route("/api/claim-approvals/pending", methods=["GET"])
def api_pending_claim_approvals():
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user_id = session["user_id"]
    approvals = list(db.claim_approvals.aggregate([
        {"$match": {"linked_user_id": user_id, "status": "Pending"}},
        {"$lookup": {"from": "expense_claims", "localField": "claim_id", "foreignField": "id", "as": "claim"}},
        {"$unwind": "$claim"},
        {"$match": {"claim.status": {"$regex": "^Pending"}}},
        {"$project": {"_id": 0, "claim._id": 0}},
        {"$sort": {"approval_sequence": 1, "created_at": 1}},
    ]))
    for approval in approvals:
        attach_approval_user_names(db, [approval])
        attach_pending_approval_display(db, approval.get("claim"), "claim_approvals", "claim_id")
    return jsonify(json_ready({"approvals": approvals}))


@app.route("/api/claim-approvals/<int:approval_id>/action", methods=["POST"])
def api_claim_approval_action(approval_id):
    if "user_id" not in session:
        abort(401)
    db = get_db()
    user = get_current_user()
    data = request.get_json() or {}
    action = data.get("action")
    if action not in {"approve", "reject"}:
        return jsonify({"error": "Invalid approval action."}), 400
    approval = db.claim_approvals.find_one({"id": approval_id, "linked_user_id": user["id"]})
    if not approval:
        return jsonify({"error": "Approval task not found for this user."}), 404
    if approval.get("status") != "Pending":
        return jsonify({"error": "This approval task is not pending."}), 400
    claim = db.expense_claims.find_one({"id": approval.get("claim_id")})
    if not claim or not str(claim.get("status", "")).startswith("Pending"):
        return jsonify({"error": "Claim is not pending stakeholder approval."}), 400
    now = datetime.now()
    remarks = data.get("remarks", "")
    final_status = "Approved" if action == "approve" else "Rejected"
    db.claim_approvals.update_one(
        {"id": approval_id},
        {"$set": {
            "status": final_status,
            "remarks": remarks,
            "action_at": now,
            "action_by_id": user["id"],
            "action_by_name": user.get("full_name"),
        }},
    )
    audit = {
        "id": get_next_sequence_value("claim_approval_audit"),
        "claim_id": claim["id"],
        "approval_id": approval_id,
        "stakeholder_id": approval.get("stakeholder_id"),
        "stakeholder_name": approval.get("stakeholder_name"),
        "linked_user_id": user["id"],
        "approval_sequence": approval.get("approval_sequence"),
        "action": final_status,
        "remarks": remarks,
        "created_at": now,
    }
    db.claim_approval_audit.insert_one(audit)
    if action == "reject":
        db.claim_approvals.update_many(
            {"claim_id": claim["id"], "status": {"$in": ["Pending", "Waiting"]}},
            {"$set": {"status": "Skipped", "updated_at": now}},
        )
        db.expense_claims.update_one(
            {"id": claim["id"]},
            {"$set": {"status": "Rejected", "rejected_at": now, "rejected_by_id": user["id"], "approval_completed": False, "updated_at": now}},
        )
        create_system_notification(db, claim.get("created_by_id"), "Expense claim rejected", f"{claim.get('claim_number')} was rejected.", "/finance/claims")
        return jsonify({"success": True, "status": "Rejected"})

    remaining_current = db.claim_approvals.count_documents({
        "claim_id": claim["id"],
        "approval_sequence": approval.get("approval_sequence"),
        "status": "Pending",
    })
    if remaining_current:
        status = pending_approval_status(db, "claim_approvals", "claim_id", claim["id"], approval.get("approval_sequence"))
        db.expense_claims.update_one({"id": claim["id"]}, {"$set": {"status": status, "updated_at": now}})
        return jsonify({"success": True, "status": status})
    next_step = db.claim_approvals.find_one(
        {"claim_id": claim["id"], "status": "Waiting"},
        sort=[("approval_sequence", 1), ("id", 1)],
    )
    if next_step:
        next_sequence = int(next_step.get("approval_sequence") or 999)
        db.claim_approvals.update_many(
            {"claim_id": claim["id"], "approval_sequence": next_sequence, "status": "Waiting"},
            {"$set": {"status": "Pending", "updated_at": now}},
        )
        status = pending_approval_status(db, "claim_approvals", "claim_id", claim["id"], next_sequence)
        db.expense_claims.update_one(
            {"id": claim["id"]},
            {"$set": {"status": status, "current_approval_sequence": next_sequence, "updated_at": now}},
        )
        for step in db.claim_approvals.find({"claim_id": claim["id"], "approval_sequence": next_sequence, "status": "Pending"}):
            create_system_notification(db, step.get("linked_user_id"), "Expense claim approval pending", f"{claim.get('claim_number')} is waiting for your approval.", "/claims/approvals")
        return jsonify({"success": True, "status": status})

    db.expense_claims.update_one(
        {"id": claim["id"]},
        {"$set": {
            "status": "Approved",
            "approval_completed": True,
            "approved_at": now,
            "updated_at": now,
        }},
    )
    create_system_notification(db, claim.get("created_by_id"), "Expense claim approved", f"{claim.get('claim_number')} is fully approved.", "/finance/claims")
    finance_users = db.app_users.find({"has_finance_access": 1, "is_active": {"$ne": 0}}, {"id": 1})
    for finance_user in finance_users:
        create_system_notification(db, finance_user.get("id"), "Claim ready for posting", f"{claim.get('claim_number')} is approved and ready for posting.", "/finance/claims")
    return jsonify({"success": True, "status": "Approved"})


@app.route("/api/finance/expense-claims/<int:claim_id>", methods=["GET", "PUT"])
def api_expense_claim_detail(claim_id):
    require_finance_access()
    db = get_db()
    claim = db.expense_claims.find_one({"id": claim_id}, {"_id": 0})
    if not claim:
        abort(404)
    if request.method == "PUT":
        if claim.get("status") not in CLAIM_EDITABLE_STATUSES:
            return jsonify({"error": "Claims cannot be edited after submission for approval."}), 400
        data = request.get_json() or {}
        status = data.get("status", claim.get("status"))
        if status not in EXPENSE_CLAIM_STATUSES:
            return jsonify({"error": "Invalid claim status."}), 400
        amount = parse_float(data.get("amount"), claim.get("amount"))
        gst_percent = parse_float(data.get("gst_percent"), claim.get("gst_percent"))
        gst_amount = parse_float(data.get("gst_amount"), claim.get("gst_amount"))
        if gst_percent:
            gst_amount = round(amount * (gst_percent / 100.0), 2)
        update_data = {
            "employee_name": (data.get("employee_name", claim.get("employee_name")) or "").strip(),
            "department": (data.get("department", claim.get("department")) or "").strip(),
            "claim_date": data.get("claim_date", claim.get("claim_date")),
            "expense_date": data.get("expense_date", claim.get("expense_date")),
            "expense_category": data.get("expense_category", claim.get("expense_category")),
            "expense_description": data.get("expense_description", claim.get("expense_description")),
            "amount": amount,
            "gst_percent": gst_percent,
            "gst_amount": gst_amount,
            "total_claim_amount": parse_float(data.get("total_claim_amount"), amount + gst_amount),
            "payment_mode": data.get("payment_mode", claim.get("payment_mode")),
            "attachment": data.get("attachment", claim.get("attachment")),
            "remarks": data.get("remarks", claim.get("remarks")),
            "status": status,
            "updated_at": datetime.now(),
        }
        old_claim = db.expense_claims.find_one({"id": claim_id})
        db.expense_claims.update_one({"id": claim_id}, {"$set": update_data})
        if status == "Submitted" and claim.get("status") != "Submitted":
            initialize_claim_approval_workflow(db, claim_id, get_current_user())
        new_claim = db.expense_claims.find_one({"id": claim_id})
        log_activity_async("Finance", "Expense Claim", claim_id, "UPDATE", old_data=old_claim, new_data=new_claim, reference_number=claim.get("claim_number"))
        return jsonify({"success": True})
    attach_pending_approval_display(db, claim, "claim_approvals", "claim_id")
    return jsonify(json_ready({"claim": claim_summary(claim)}))


@app.route("/api/finance/expense-claims/<int:claim_id>/action", methods=["POST"])
def api_expense_claim_action(claim_id):
    require_finance_access()
    db = get_db()
    claim = db.expense_claims.find_one({"id": claim_id})
    if not claim:
        abort(404)
    data = request.get_json() or {}
    action = data.get("action")
    actor = get_current_user()

    def set_status(status, extra=None):
        update = {"status": status, "updated_at": datetime.now()}
        if extra:
            update.update(extra)
        db.expense_claims.update_one({"id": claim_id}, {"$set": update})
        log_activity_async("Finance", "Expense Claim", claim_id, "UPDATE", old_data=claim, new_data=db.expense_claims.find_one({"id": claim_id}), reference_number=claim.get("claim_number"))
        return jsonify({"success": True, "status": status})

    if action == "submit":
        if claim.get("status") != "Draft":
            return jsonify({"error": "Only draft claims can be submitted."}), 400
        status = initialize_claim_approval_workflow(db, claim_id, actor)
        return jsonify({"success": True, "status": status})
    if action == "review":
        if active_claim_approvers(db):
            return jsonify({"error": "Submitted claims must follow stakeholder approval workflow."}), 400
        if claim.get("status") != "Submitted":
            return jsonify({"error": "Only submitted claims can move under review."}), 400
        return set_status("Under Review")
    if action == "approve":
        if active_claim_approvers(db):
            return jsonify({"error": "Claims must be approved by linked stakeholders in sequence."}), 400
        if claim.get("status") not in {"Submitted", "Under Review"}:
            return jsonify({"error": "Only submitted or under-review claims can be approved."}), 400
        return set_status("Approved", {"approved_at": datetime.now(), "approved_by": actor["id"] if actor else None})
    if action == "reject":
        if active_claim_approvers(db):
            return jsonify({"error": "Submitted claims can only be rejected by the assigned stakeholder approver."}), 400
        if claim.get("status") in {"Posted", "Settled"}:
            return jsonify({"error": "Posted or settled claims cannot be rejected."}), 400
        return set_status("Rejected", {"rejection_reason": data.get("remarks") or data.get("reason")})
    if action == "cancel":
        if claim.get("status") != "Draft":
            return jsonify({"error": "Claims cannot be cancelled after submission for approval."}), 400
        return set_status("Cancelled")
    if action == "post":
        if claim.get("status") != "Approved":
            return jsonify({"error": "Only approved claims can be posted."}), 400
        if claim_has_active_posted_transaction(db, claim):
            return jsonify({"error": "This claim has already been posted."}), 400
        ensure_default_accounts(db)
        expense_account = db.accounts.find_one({"name": "Operating Expenses"}) or db.accounts.find_one({"type": "Expense"})
        base_amount, cgst_amount, cgst_percent, total_claim_amount = claim_gst_breakdown(
            claim.get("amount"),
            claim.get("gst_percent"),
            claim.get("gst_amount"),
            claim.get("total_claim_amount"),
        )
        tx = create_finance_transaction(db, {
            "account_id": expense_account.get("id") if expense_account else None,
            "transaction_date": data.get("posting_date") or claim.get("expense_date"),
            "description": f"Expense claim {claim.get('claim_number')}: {claim.get('expense_description')}",
            "type": "Expense",
            "amount": base_amount,
            "cgst_percent": cgst_percent,
            "cgst_amount": cgst_amount,
            "total_amount": total_claim_amount,
            "currency": data.get("currency") or "INR",
            "reference": claim.get("claim_number"),
            "category": claim.get("expense_category") or "Employee Expense Claim",
            "expense_claim_id": claim_id,
            "attachments": [claim.get("attachment")] if claim.get("attachment") else [],
        }, actor)
        sync_transaction_to_treasury_revenue(db, tx)
        return set_status("Posted", {"posted_transaction_id": tx["id"], "posted_at": datetime.now(), "posted_by": actor["id"] if actor else None})
    if action == "settle":
        if claim.get("status") != "Posted":
            return jsonify({"error": "Only posted claims can be settled."}), 400
        if claim.get("settlement_transaction_id"):
            return jsonify({"error": "This claim is already settled."}), 400
        expense_account = db.accounts.find_one({"name": "Operating Expenses"}) or db.accounts.find_one({"type": "Expense"})
        tx = create_finance_transaction(db, {
            "account_id": expense_account.get("id") if expense_account else None,
            "transaction_date": data.get("settlement_date") or datetime.now().strftime("%Y-%m-%d"),
            "description": f"Settlement for expense claim {claim.get('claim_number')}",
            "type": "Expense",
            "amount": claim.get("total_claim_amount"),
            "total_amount": claim.get("total_claim_amount"),
            "currency": data.get("currency") or "INR",
            "reference": data.get("reference") or f"SETTLE-{claim.get('claim_number')}",
            "category": "Expense Claim Settlement",
            "expense_claim_id": claim_id,
        }, actor)
        sync_transaction_to_treasury_revenue(db, tx)
        return set_status("Settled", {"settlement_transaction_id": tx["id"], "settled_at": datetime.now(), "settled_by": actor["id"] if actor else None})
    return jsonify({"error": "Invalid claim action."}), 400


@app.route("/api/treasury/loans", methods=["GET", "POST"])
def api_treasury_loans():
    user = require_treasury_access()
    db = get_db()
    if request.method == "POST":
        data = request.get_json() or {}
        status = data.get("status", "Draft")
        if status not in LOAN_STATUSES:
            return jsonify({"error": "Invalid loan status."}), 400
        provider_type = data.get("provider_type", "Bank")
        if provider_type not in LOAN_PROVIDER_TYPES:
            return jsonify({"error": "Invalid loan provider type."}), 400
        loan_id = get_next_sequence_value("loan_accounts")
        doc = {
            "id": loan_id,
            "loan_account_number": data.get("loan_account_number") or f"LOAN-{loan_id:04d}",
            "provider_type": provider_type,
            "provider_name": data.get("provider_name"),
            "total_loan_amount": parse_float(data.get("total_loan_amount")),
            "interest_rate": parse_float(data.get("interest_rate")),
            "interest_type": data.get("interest_type", "Fixed"),
            "tenure": parse_float(data.get("tenure")),
            "tenure_unit": data.get("tenure_unit", "Months"),
            "start_date": data.get("start_date"),
            "end_date": data.get("end_date"),
            "repayment_frequency": data.get("repayment_frequency", "Monthly"),
            "bank_account_id": safe_int(data.get("bank_account_id")),
            "purpose": data.get("purpose"),
            "agreement_attachment": data.get("agreement_attachment"),
            "remarks": data.get("remarks"),
            "status": status,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": user["id"],
        }
        if doc["interest_type"] not in LOAN_INTEREST_TYPES or doc["tenure_unit"] not in LOAN_TENURE_UNITS or doc["repayment_frequency"] not in LOAN_REPAYMENT_FREQUENCIES:
            return jsonify({"error": "Invalid loan configuration."}), 400
        db.loan_accounts.insert_one(doc)
        log_treasury_action(user["id"], "Created Loan Account", f"Created loan account {doc['loan_account_number']}.")
        return jsonify(json_ready({"loan": {k: v for k, v in doc.items() if k != "_id"}}))
    loans = list(db.loan_accounts.find({}, {"_id": 0}).sort([("created_at", -1)]))
    for loan in loans:
        loan.update(loan_totals(db, loan["id"]))
        loan["schedules"] = list(
            db.loan_repayment_schedules.find(
                {"loan_id": loan["id"], "status": {"$in": ["Unpaid", "Partially Paid"]}},
                {"_id": 0},
            ).sort("installment_number", 1)
        )
    upcoming = db.loan_repayment_schedules.count_documents({"status": "Unpaid", "due_date": {"$gte": datetime.now().strftime("%Y-%m-%d")}})
    overdue = db.loan_repayment_schedules.count_documents({"status": {"$in": ["Unpaid", "Partially Paid"]}, "due_date": {"$lt": datetime.now().strftime("%Y-%m-%d")}})
    return jsonify(json_ready({
        "loans": loans,
        "stats": {
            "active_loans": sum(1 for loan in loans if loan.get("status") == "Active"),
            "total_loan_amount": sum(parse_float(loan.get("total_loan_amount")) for loan in loans if loan.get("status") != "Cancelled"),
            "total_disbursed_amount": sum(parse_float(loan.get("total_disbursed_amount")) for loan in loans),
            "outstanding_loan_balance": sum(parse_float(loan.get("outstanding_balance")) for loan in loans),
            "upcoming_repayments": upcoming,
            "overdue_repayments": overdue,
        }
    }))


@app.route("/api/treasury/loans/<int:loan_id>", methods=["GET", "PUT"])
def api_treasury_loan_detail(loan_id):
    user = require_treasury_access()
    db = get_db()
    loan = db.loan_accounts.find_one({"id": loan_id}, {"_id": 0})
    if not loan:
        abort(404)
    if request.method == "PUT":
        data = request.get_json() or {}
        status = data.get("status", loan.get("status"))
        totals = loan_totals(db, loan_id)
        if status == "Closed" and totals["outstanding_balance"] > 0:
            return jsonify({"error": "Loan can be closed only when outstanding balance is zero."}), 400
        update = {
            "provider_type": data.get("provider_type", loan.get("provider_type")),
            "provider_name": data.get("provider_name", loan.get("provider_name")),
            "total_loan_amount": parse_float(data.get("total_loan_amount"), loan.get("total_loan_amount")),
            "interest_rate": parse_float(data.get("interest_rate"), loan.get("interest_rate")),
            "interest_type": data.get("interest_type", loan.get("interest_type")),
            "tenure": parse_float(data.get("tenure"), loan.get("tenure")),
            "tenure_unit": data.get("tenure_unit", loan.get("tenure_unit")),
            "start_date": data.get("start_date", loan.get("start_date")),
            "end_date": data.get("end_date", loan.get("end_date")),
            "repayment_frequency": data.get("repayment_frequency", loan.get("repayment_frequency")),
            "bank_account_id": safe_int(data.get("bank_account_id", loan.get("bank_account_id"))),
            "purpose": data.get("purpose", loan.get("purpose")),
            "agreement_attachment": data.get("agreement_attachment", loan.get("agreement_attachment")),
            "remarks": data.get("remarks", loan.get("remarks")),
            "status": status,
            "updated_at": datetime.now(),
        }
        db.loan_accounts.update_one({"id": loan_id}, {"$set": update})
        log_treasury_action(user["id"], "Updated Loan Account", f"Updated loan account {loan.get('loan_account_number')}.")
        return jsonify({"success": True})
    disbursements = list(db.loan_disbursements.find({"loan_id": loan_id}, {"_id": 0}).sort("disbursement_date", -1))
    schedules = list(db.loan_repayment_schedules.find({"loan_id": loan_id}, {"_id": 0}).sort("installment_number", 1))
    loan.update(loan_totals(db, loan_id))
    return jsonify(json_ready({"loan": loan, "disbursements": disbursements, "schedules": schedules}))


@app.route("/api/treasury/loans/<int:loan_id>/disbursements", methods=["POST"])
def api_treasury_loan_disbursement(loan_id):
    user = require_treasury_access()
    db = get_db()
    loan = db.loan_accounts.find_one({"id": loan_id})
    if not loan:
        abort(404)
    data = request.get_json() or {}
    amount = parse_float(data.get("amount"))
    totals = loan_totals(db, loan_id)
    if amount <= 0:
        return jsonify({"error": "Disbursement amount must be greater than zero."}), 400
    if totals["total_disbursed_amount"] + amount > parse_float(loan.get("total_loan_amount")) + 0.01:
        return jsonify({"error": "Total disbursement cannot exceed approved loan amount."}), 400
    tx = create_finance_transaction(db, {
        "account_id": safe_int(data.get("bank_account_id") or loan.get("bank_account_id")),
        "loan_account_id": loan_id,
        "transaction_date": data.get("disbursement_date") or datetime.now().strftime("%Y-%m-%d"),
        "description": f"Loan disbursement {loan.get('loan_account_number')}",
        "type": "Income",
        "amount": amount,
        "total_amount": amount,
        "currency": data.get("currency") or "INR",
        "reference": data.get("reference"),
        "category": "Loan Disbursement",
    }, user)
    sync_transaction_to_treasury_revenue(db, tx)
    disb_id = get_next_sequence_value("loan_disbursements")
    doc = {
        "id": disb_id,
        "loan_id": loan_id,
        "disbursement_date": data.get("disbursement_date") or datetime.now().strftime("%Y-%m-%d"),
        "amount": amount,
        "bank_account_id": safe_int(data.get("bank_account_id") or loan.get("bank_account_id")),
        "reference": data.get("reference"),
        "remarks": data.get("remarks"),
        "transaction_id": tx["id"],
        "status": "Posted",
        "created_at": datetime.now(),
    }
    db.loan_disbursements.insert_one(doc)
    db.loan_accounts.update_one({"id": loan_id}, {"$set": {"status": "Active", "updated_at": datetime.now()}})
    log_treasury_action(user["id"], "Posted Loan Disbursement", f"Posted disbursement of {amount:.2f} for {loan.get('loan_account_number')}.")
    return jsonify(json_ready({"disbursement": doc}))


@app.route("/api/treasury/loans/<int:loan_id>/schedules", methods=["POST"])
def api_treasury_loan_schedule(loan_id):
    user = require_treasury_access()
    db = get_db()
    loan = db.loan_accounts.find_one({"id": loan_id})
    if not loan:
        abort(404)
    data = request.get_json() or {}
    schedule_id = get_next_sequence_value("loan_repayment_schedules")
    principal = parse_float(data.get("principal_amount"))
    interest = parse_float(data.get("interest_amount"))
    doc = {
        "id": schedule_id,
        "loan_id": loan_id,
        "installment_number": int(data.get("installment_number") or (db.loan_repayment_schedules.count_documents({"loan_id": loan_id}) + 1)),
        "due_date": data.get("due_date"),
        "principal_amount": principal,
        "interest_amount": interest,
        "total_amount": parse_float(data.get("total_amount"), principal + interest),
        "paid_amount": 0.0,
        "status": "Unpaid",
        "transaction_id": None,
        "created_at": datetime.now(),
    }
    db.loan_repayment_schedules.insert_one(doc)
    log_treasury_action(user["id"], "Added Loan Repayment Schedule", f"Added installment {doc['installment_number']} for {loan.get('loan_account_number')}.")
    return jsonify(json_ready({"schedule": doc}))


@app.route("/api/treasury/loan-schedules/<int:schedule_id>/status", methods=["PUT"])
def api_treasury_loan_schedule_status(schedule_id):
    user = require_treasury_access()
    db = get_db()
    schedule = db.loan_repayment_schedules.find_one({"id": schedule_id})
    if not schedule:
        abort(404)
    data = request.get_json() or {}
    status = data.get("status")
    if status == "Unpaid":
        db.loan_repayment_schedules.update_one({"id": schedule_id}, {"$set": {"status": "Unpaid", "transaction_id": None, "paid_amount": 0.0, "updated_at": datetime.now()}})
        return jsonify({"success": True})
    if status not in {"Paid", "Partially Paid"}:
        return jsonify({"error": "Invalid schedule status."}), 400
    transaction_id = data.get("transaction_id")
    if not transaction_id:
        return jsonify({"error": "Link a repayment transaction before marking this schedule as paid."}), 400
    tx = db.transactions.find_one({"id": transaction_id, "type": "Expense", "status": {"$ne": "Reversed"}})
    if not tx:
        return jsonify({"error": "Select a valid expense repayment transaction."}), 400
    paid_amount = parse_float(data.get("paid_amount"), tx.get("total_amount") or tx.get("amount"))
    final_status = "Paid" if paid_amount >= parse_float(schedule.get("total_amount")) else "Partially Paid"
    db.loan_repayment_schedules.update_one({"id": schedule_id}, {"$set": {"status": final_status, "transaction_id": transaction_id, "paid_amount": paid_amount, "updated_at": datetime.now()}})
    db.transactions.update_one({"id": transaction_id}, {"$set": {"loan_account_id": schedule.get("loan_id"), "loan_schedule_id": schedule_id}})
    log_treasury_action(user["id"], "Linked Loan Repayment", f"Linked transaction #{transaction_id} to repayment schedule #{schedule_id}.")
    return jsonify({"success": True, "status": final_status})

@app.route("/api/treasury/revenue", methods=["GET", "POST"])
def api_treasury_revenue():
    user = require_treasury_access()
    db = get_db()
    
    if request.method == "POST":
        data = request.get_json() or {}
        
        amount = float(data.get("amount", 0))
        entry_date = data.get("entry_date", datetime.now().strftime("%Y-%m-%d"))
        revenue_type = data.get("revenue_type", "Sales Income")
        project_id = data.get("project_id")
        if project_id: project_id = int(project_id)
        
        reserve_percentage = 100.0
        channel_partner_id = None
        
        description = data.get("description", "")
        
        reserve_amount = amount * (reserve_percentage / 100.0)
        partner_commission = 0.0
        stakeholder_total = 0.0
        
        rev_id = get_next_sequence_value("treasury_revenue")
        revenue_id_str = f"REV-{rev_id}"
        
        db.treasury_revenue.insert_one({
            "id": rev_id,
            "revenue_id": revenue_id_str,
            "project_id": project_id,
            "entry_date": entry_date,
            "date": datetime.strptime(entry_date, "%Y-%m-%d"),
            "revenue_type": revenue_type,
            "amount": amount,
            "reserve_percentage": reserve_percentage,
            "reserve_amount": reserve_amount,
            "channel_partner_id": channel_partner_id,
            "partner_commission": partner_commission,
            "stakeholder_total": stakeholder_total,
            "description": description,
            "is_settled": False,
            "created_at": datetime.now()
        })
                
        log_treasury_action(user["id"], "Logged Revenue", f"Recorded revenue entry {revenue_id_str} (pending settlement).")
        return jsonify({"ok": True})
        
    purge_orphaned_unsettled_transaction_revenue(db)
    purge_unsettled_revenue_payouts(db)
    normalize_stakeholder_flow_payouts(db)

    # Auto-sync ledger transactions from db.transactions (only active ones, not Reversed)
    all_txns = list(db.transactions.find({"status": {"$ne": "Reversed"}}))
    
    for t in all_txns:
        existing = db.treasury_revenue.find_one({"transaction_id": t["id"]})
        amount = float(t.get("total_amount") or t.get("amount") or 0.0)
        txn_currency = (t.get("currency") or "INR").upper()
        if txn_currency != "INR":
            conversion_rates = {"USD": 95.0, "EUR": 102.0, "GBP": 120.0}
            rate = conversion_rates.get(txn_currency, 95.0)
            amount = amount * rate
            
        is_expense = t.get("type") == "Expense"
        
        # Expenses flow as negative in amounts, Incomes as positive
        if is_expense:
            amount = -abs(amount)
            reserve_percentage = 100.0
            reserve_amount = amount
            partner_commission = 0.0
            stakeholder_total = 0.0
            revenue_type = "Company Expense"
        else:
            amount = abs(amount)
            reserve_percentage = 100.0
            reserve_amount = amount
            partner_commission = 0.0
            stakeholder_total = 0.0
            revenue_type = "Sales Income"
            
        entry_date = t.get("transaction_date") or t.get("date") or datetime.now().strftime("%Y-%m-%d")
        if not existing:
            rev_id = get_next_sequence_value("treasury_revenue")
            revenue_id_str = f"REV-{rev_id}"
            
            db.treasury_revenue.insert_one({
                "id": rev_id,
                "revenue_id": revenue_id_str,
                "transaction_id": t["id"],
                "project_id": t.get("project_id"),
                "entry_date": entry_date,
                "date": datetime.strptime(entry_date, "%Y-%m-%d") if isinstance(entry_date, str) else entry_date,
                "revenue_type": revenue_type,
                "amount": amount,
                "reserve_percentage": reserve_percentage,
                "reserve_amount": reserve_amount,
                "channel_partner_id": None,
                "partner_commission": partner_commission,
                "stakeholder_total": stakeholder_total,
                "description": t.get("description") or f"Auto-flow from Transaction Ledger #{t['id']}",
                "is_settled": False,
                "created_at": datetime.now()
            })
            if amount < 0:
                create_or_update_payable_from_revenue(db, db.treasury_revenue.find_one({"id": rev_id}))
        elif not existing.get("is_settled"):
            db.treasury_revenue.update_one(
                {"id": existing["id"]},
                {"$set": {
                    "project_id": t.get("project_id"),
                    "entry_date": entry_date,
                    "date": datetime.strptime(entry_date, "%Y-%m-%d") if isinstance(entry_date, str) else entry_date,
                    "revenue_type": revenue_type,
                    "amount": amount,
                    "reserve_percentage": reserve_percentage,
                    "reserve_amount": reserve_amount,
                    "channel_partner_id": None,
                    "partner_commission": partner_commission,
                    "stakeholder_total": stakeholder_total,
                    "description": t.get("description") or f"Auto-flow from Transaction Ledger #{t['id']}",
                    "updated_at": datetime.now()
                }}
            )
            if amount < 0:
                create_or_update_payable_from_revenue(db, db.treasury_revenue.find_one({"id": existing["id"]}))
                        
    revenues = list(db.treasury_revenue.aggregate([
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"project_name": "$project.project_name"}},
        {"$project": {"project": 0, "_id": 0}},
        {"$sort": {"entry_date": -1, "created_at": -1}}
    ]))
    return jsonify(json_ready({"revenue": revenues}))

@app.route("/api/treasury/revenue/<int:revenue_id>", methods=["PUT"])
def api_treasury_revenue_update(revenue_id):
    user = require_treasury_access()
    db = get_db()
    data = request.get_json() or {}
    
    rev = db.treasury_revenue.find_one({"id": revenue_id})
    if not rev:
        return jsonify({"error": "Revenue split record not found."}), 404

    if rev.get("is_settled"):
        return jsonify({"error": "This revenue entry is settled and cannot be edited."}), 403
        
    amount = float(rev.get("amount", 0.0))
    entry_date = rev.get("entry_date", datetime.now().strftime("%Y-%m-%d"))
    if amount < 0:
        create_or_update_payable_from_revenue(db, rev)
        return jsonify({"error": "Expense entries are payable-managed. Open Payables and mark the payable as paid to deduct company fund."}), 400
    
    reserve_percentage = 100.0
    channel_partner_id = None
    partner_commission = 0.0
    reserve_amount = amount * (reserve_percentage / 100.0)
    stakeholder_total = 0.0
    
    # Update revenue document and mark settled (100% split confirmed)
    db.treasury_revenue.update_one(
        {"id": revenue_id},
        {"$set": {
            "reserve_percentage": reserve_percentage,
            "reserve_amount": reserve_amount,
            "channel_partner_id": channel_partner_id,
            "partner_commission": partner_commission,
            "stakeholder_total": stakeholder_total,
            "is_settled": True,
            "settled_at": datetime.now(),
            "settled_by": user["id"],
        }}
    )
    
    # Reset existing payouts for this revenue entry
    db.treasury_payouts.delete_many({"revenue_id": revenue_id})
    
    # Re-insert company fund allocation only for inflows. Outflows become
    # payables and reduce company fund only when the payable is marked paid.
    is_neg = reserve_amount < 0
    if is_neg:
        create_or_update_payable_from_revenue(db, db.treasury_revenue.find_one({"id": revenue_id}))
    else:
        db.treasury_payouts.insert_one({
            "id": get_next_sequence_value("treasury_payouts"),
            "revenue_id": revenue_id,
            "payout_type": "Reserve Fund",
            "amount": abs(reserve_amount),
            "status": "Completed",
            "payout_date": entry_date,
            "description": f"Company fund allocation for REV-{revenue_id}",
            "created_at": datetime.now()
        })

    entry_kind = "company expense" if amount < 0 else "company fund receipt"
    log_treasury_action(
        user["id"],
        "Revenue Settled",
        f"Settled REV-{revenue_id} as {entry_kind}; 100% allocated to company fund. Entry is locked.",
    )
    return jsonify({"ok": True, "is_settled": True})

@app.route("/api/treasury/payouts", methods=["GET"])
def api_treasury_payouts():
    user = require_treasury_access()
    db = get_db()
    purge_orphaned_unsettled_transaction_revenue(db)
    purge_unsettled_revenue_payouts(db)
    normalize_stakeholder_flow_payouts(db)
    settled_revenue_ids = get_settled_revenue_ids(db)
    reserve_balance_match = reserve_balance_payout_clause(settled_revenue_ids)
    
    payouts = list(db.treasury_payouts.aggregate([
        {"$match": reserve_balance_match},
        {"$lookup": {"from": "treasury_revenue", "localField": "revenue_id", "foreignField": "id", "as": "rev"}},
        {"$unwind": {"path": "$rev", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "rev.project_id", "foreignField": "id", "as": "proj"}},
        {"$unwind": {"path": "$proj", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "treasury_stakeholders", "localField": "stakeholder_id", "foreignField": "id", "as": "stk"}},
        {"$unwind": {"path": "$stk", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "treasury_partners", "localField": "partner_id", "foreignField": "id", "as": "part"}},
        {"$unwind": {"path": "$part", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "project_name": "$proj.project_name",
            "stakeholder_name": "$stk.name",
            "partner_name": "$part.name",
            "payout_date": {"$ifNull": ["$payout_date", "$rev.entry_date"]}
        }},
        {"$project": {"rev": 0, "proj": 0, "stk": 0, "part": 0, "_id": 0}},
        {"$sort": {"created_at": -1}}
    ]))
    
    return jsonify(json_ready({"payouts": payouts}))

@app.route("/api/treasury/payouts/<int:pid>/status", methods=["PUT"])
def api_treasury_payout_status(pid):
    user = require_treasury_access()
    db = get_db()
    data = request.get_json() or {}
    status = data.get("status", "Pending")
    
    if status not in ["Pending", "Paid"]:
        return jsonify({"error": "Invalid status."}), 400
        
    db.treasury_payouts.update_one({"id": pid}, {"$set": {"status": status}})
    log_treasury_action(user["id"], "Updated Payout Status", f"Updated payout ID {pid} to status '{status}'.")
    return jsonify({"ok": True})

@app.route("/api/treasury/logs", methods=["GET"])
def api_treasury_logs():
    user = require_treasury_access()
    db = get_db()
    
    logs = list(db.treasury_logs.aggregate([
        {"$lookup": {"from": "app_users", "localField": "user_id", "foreignField": "id", "as": "user"}},
        {"$unwind": {"path": "$user", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"user_name": "$user.full_name"}},
        {"$project": {"user": 0, "_id": 0}},
        {"$sort": {"created_at": -1}},
        {"$limit": 100}
    ]))
    return jsonify(json_ready({"logs": logs}))


@app.route("/api/vault/categories", methods=["GET"])
def api_vault_categories():
    require_vault_access()
    return jsonify(json_ready({"categories": VAULT_CATEGORIES}))


@app.route("/api/vault/status", methods=["GET"])
def api_vault_status():
    user = require_vault_access()
    return jsonify({
        "code_configured": bool(user.get("vault_access_code_hash")),
        "unlocked": session.get("vault_unlocked_user_id") == user.get("id"),
    })


@app.route("/api/vault/unlock", methods=["POST"])
def api_vault_unlock():
    user = require_vault_access()
    data = request.get_json() or {}
    access_code = (data.get("access_code") or "").strip()
    code_hash = user.get("vault_access_code_hash")
    if not code_hash:
        return jsonify({"error": "Vault access code is not set for this user."}), 403
    if not access_code or not check_password_hash(code_hash, access_code):
        log_vault_action(user["id"], "Failed Unlock", "Incorrect vault access code.")
        return jsonify({"error": "Invalid vault access code."}), 403
    session["vault_unlocked_user_id"] = user["id"]
    log_vault_action(user["id"], "Unlocked Vault", "Vault access code accepted.")
    log_activity_async(
        "Vault",
        "Access",
        user["id"],
        "UNLOCK",
        new_data={"result": "success", "user_id": user["id"], "user_name": user.get("full_name")},
        reference_number=user.get("email"),
    )
    return jsonify({"success": True})


@app.route("/api/vault/lock", methods=["POST"])
def api_vault_lock():
    require_vault_access()
    session.pop("vault_unlocked_user_id", None)
    return jsonify({"success": True})


@app.route("/api/vault", methods=["GET", "POST"])
def api_vault_entries():
    user, error_response = require_vault_unlocked()
    if error_response:
        return error_response
    db = get_db()

    if request.method == "POST":
        data = request.get_json() or {}
        title = (data.get("title") or "").strip()
        category = (data.get("category") or "Other").strip()
        if not title:
            return jsonify({"error": "Title is required."}), 400
        if category not in VAULT_CATEGORIES:
            return jsonify({"error": "Invalid category."}), 400

        customer_id = data.get("customer_id")
        if customer_id in ("", None):
            customer_id = None
        else:
            customer_id = int(customer_id)

        project_id = data.get("project_id")
        if project_id in ("", None):
            project_id = None
        else:
            project_id = int(project_id)

        entry_id = get_next_sequence_value("vault_entries")
        now = datetime.now()
        insert_data = {
            "id": entry_id,
            "title": title,
            "category": category,
            "login_id": (data.get("login_id") or "").strip(),
            "password_encrypted": encrypt_vault_secret(data.get("password") or ""),
            "notes": (data.get("notes") or "").strip(),
            "url": (data.get("url") or "").strip(),
            "customer_id": customer_id,
            "project_id": project_id,
            "created_by_id": user["id"],
            "updated_by_id": user["id"],
            "created_at": now,
            "updated_at": now,
        }
        db.vault_entries.insert_one(insert_data)
        log_vault_action(user["id"], "Created Credential", f"Added vault entry '{title}' ({category}).")
        activity_data = {k: v for k, v in insert_data.items() if k != "password_encrypted"}
        activity_data["has_password"] = bool(insert_data.get("password_encrypted"))
        log_activity_async("Vault", "Credential", entry_id, "CREATE", new_data=activity_data, reference_number=title)
        return jsonify({"ok": True, "id": entry_id})

    query = {}
    category = request.args.get("category")
    if category and category != "All":
        query["category"] = category
    search = (request.args.get("search") or "").strip()
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"login_id": {"$regex": search, "$options": "i"}},
            {"notes": {"$regex": search, "$options": "i"}},
            {"url": {"$regex": search, "$options": "i"}},
        ]

    entries = list(db.vault_entries.aggregate([
        {"$match": query},
        {"$lookup": {"from": "customers", "localField": "customer_id", "foreignField": "id", "as": "customer"}},
        {"$unwind": {"path": "$customer", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "projects", "localField": "project_id", "foreignField": "id", "as": "project"}},
        {"$unwind": {"path": "$project", "preserveNullAndEmptyArrays": True}},
        {"$lookup": {"from": "app_users", "localField": "updated_by_id", "foreignField": "id", "as": "editor"}},
        {"$unwind": {"path": "$editor", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {
            "customer_name": "$customer.company_name",
            "project_name": "$project.project_name",
            "updated_by_name": "$editor.full_name",
            "has_password": {
                "$gt": [{"$strLenCP": {"$ifNull": ["$password_encrypted", ""]}}, 0]
            },
        }},
        {"$project": {"customer": 0, "project": 0, "editor": 0, "_id": 0, "password_encrypted": 0}},
        {"$sort": {"updated_at": -1, "title": 1}},
    ]))

    category_counts = {
        doc["_id"]: doc["count"]
        for doc in db.vault_entries.aggregate([
            {"$group": {"_id": "$category", "count": {"$sum": 1}}},
        ])
    }

    return jsonify(json_ready({
        "entries": entries,
        "categories": VAULT_CATEGORIES,
        "category_counts": category_counts,
        "total": len(entries),
    }))


@app.route("/api/vault/<int:entry_id>", methods=["GET", "PUT", "DELETE"])
def api_vault_entry_detail(entry_id):
    user, error_response = require_vault_unlocked()
    if error_response:
        return error_response
    db = get_db()
    doc = db.vault_entries.find_one({"id": entry_id})
    if not doc:
        return jsonify({"error": "Vault entry not found."}), 404

    if request.method == "GET":
        reveal = request.args.get("reveal") in ("1", "true", "yes")
        entry = serialize_vault_entry(doc, include_secrets=reveal)
        if doc.get("customer_id"):
            customer = db.customers.find_one({"id": doc["customer_id"]}, {"_id": 0, "id": 1, "company_name": 1})
            entry["customer_name"] = customer.get("company_name") if customer else None
        if doc.get("project_id"):
            project = db.projects.find_one({"id": doc["project_id"]}, {"_id": 0, "id": 1, "project_name": 1})
            entry["project_name"] = project.get("project_name") if project else None
        if reveal:
            log_vault_action(user["id"], "Viewed Credential", f"Revealed password for '{doc.get('title')}'.")
            log_activity_async(
                "Vault",
                "Credential",
                entry_id,
                "VIEW_PASSWORD",
                new_data={
                    "title": doc.get("title"),
                    "category": doc.get("category"),
                    "viewed_password": True,
                    "customer_id": doc.get("customer_id"),
                    "project_id": doc.get("project_id"),
                },
                reference_number=doc.get("title"),
            )
        return jsonify(json_ready({"entry": entry}))

    if request.method == "DELETE":
        db.vault_entries.delete_one({"id": entry_id})
        log_vault_action(user["id"], "Deleted Credential", f"Removed vault entry '{doc.get('title')}'.")
        old_data = {k: v for k, v in doc.items() if k not in ("_id", "password_encrypted")}
        old_data["has_password"] = bool(doc.get("password_encrypted"))
        log_activity_async("Vault", "Credential", entry_id, "DELETE", old_data=old_data, reference_number=doc.get("title"))
        return jsonify({"ok": True})

    data = request.get_json() or {}
    title = (data.get("title") or doc.get("title") or "").strip()
    category = (data.get("category") or doc.get("category") or "Other").strip()
    if not title:
        return jsonify({"error": "Title is required."}), 400
    if category not in VAULT_CATEGORIES:
        return jsonify({"error": "Invalid category."}), 400

    customer_id = data.get("customer_id", doc.get("customer_id"))
    if customer_id in ("", None):
        customer_id = None
    elif customer_id is not None:
        customer_id = int(customer_id)

    project_id = data.get("project_id", doc.get("project_id"))
    if project_id in ("", None):
        project_id = None
    elif project_id is not None:
        project_id = int(project_id)

    update_fields = {
        "title": title,
        "category": category,
        "login_id": (data.get("login_id") if "login_id" in data else doc.get("login_id") or "").strip(),
        "notes": (data.get("notes") if "notes" in data else doc.get("notes") or "").strip(),
        "url": (data.get("url") if "url" in data else doc.get("url") or "").strip(),
        "customer_id": customer_id,
        "project_id": project_id,
        "updated_by_id": user["id"],
        "updated_at": datetime.now(),
    }
    if "password" in data:
        update_fields["password_encrypted"] = encrypt_vault_secret(data.get("password") or "")

    db.vault_entries.update_one({"id": entry_id}, {"$set": update_fields})
    log_vault_action(user["id"], "Updated Credential", f"Updated vault entry '{title}' ({category}).")
    old_data = {k: v for k, v in doc.items() if k not in ("_id", "password_encrypted")}
    old_data["has_password"] = bool(doc.get("password_encrypted"))
    new_doc = db.vault_entries.find_one({"id": entry_id})
    new_data = {k: v for k, v in new_doc.items() if k not in ("_id", "password_encrypted")}
    new_data["has_password"] = bool(new_doc.get("password_encrypted"))
    log_activity_async("Vault", "Credential", entry_id, "UPDATE", old_data=old_data, new_data=new_data, reference_number=title)
    return jsonify({"ok": True})


@app.route("/api/vault/logs", methods=["GET"])
def api_vault_logs():
    user, error_response = require_vault_unlocked()
    if error_response:
        return error_response
    db = get_db()
    logs = list(db.vault_logs.aggregate([
        {"$lookup": {"from": "app_users", "localField": "user_id", "foreignField": "id", "as": "user"}},
        {"$unwind": {"path": "$user", "preserveNullAndEmptyArrays": True}},
        {"$addFields": {"user_name": "$user.full_name"}},
        {"$project": {"user": 0, "_id": 0}},
        {"$sort": {"created_at": -1}},
        {"$limit": 100},
    ]))
    return jsonify(json_ready({"logs": logs}))


if __name__ == "__main__":
    app.run(debug=True)
