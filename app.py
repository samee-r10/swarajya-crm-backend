import json
import os
import re
from base64 import urlsafe_b64encode
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal
from hashlib import sha256

import pymongo
from cryptography.fernet import Fernet, InvalidToken
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.security import check_password_hash, generate_password_hash
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
]
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

# ── Session cookie settings ────────────────────────────────────────────────────
# "None" + Secure is required for cross-site cookies (frontend on Vercel,
# backend on Vercel = different subdomains so treat as cross-site).
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
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
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    return value


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
        "accounts": [
            ("Name", "name", "Text", 1),
            ("Type", "type", "Dropdown", 1, '["Asset", "Liability", "Equity", "Revenue", "Expense"]'),
            ("Balance", "balance", "Number", 1),
            ("System Default", "is_system_default", "Checkbox", 0),
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

def init_database():
    db = get_db()
    
    # Initialize basic collections
    collections = db.list_collection_names()
    if "counters" not in collections:
        db.create_collection("counters")
        
    # Seed custom objects
    standard_objects = [
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Customer', 'plural_label': 'Customers', 'api_name': 'customers', 'is_standard': 1, 'storage_table': 'customers', 'description': 'Standard customer object.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Opportunity', 'plural_label': 'Opportunities', 'api_name': 'opportunities', 'is_standard': 1, 'storage_table': 'opportunities', 'description': 'Standard sales opportunity object.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Project', 'plural_label': 'Projects', 'api_name': 'projects', 'is_standard': 1, 'storage_table': 'projects', 'description': 'Standard delivery project object.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Vendor', 'plural_label': 'Vendors', 'api_name': 'vendors', 'is_standard': 1, 'storage_table': 'vendors', 'description': 'Standard vendor object for finance.', 'created_at': datetime.now()},
        {'id': get_next_sequence_value('custom_objects'), 'label': 'Account', 'plural_label': 'Accounts', 'api_name': 'accounts', 'is_standard': 1, 'storage_table': 'accounts', 'description': 'Standard account object for finance.', 'created_at': datetime.now()},
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
            {"id": get_next_sequence_value("accounts"), "name": "Cash on Hand", "type": "Asset", "balance": 0, "is_system_default": 1, "created_at": datetime.now()},
            {"id": get_next_sequence_value("accounts"), "name": "Bank Account", "type": "Asset", "balance": 0, "is_system_default": 1, "created_at": datetime.now()},
            {"id": get_next_sequence_value("accounts"), "name": "Sales Revenue", "type": "Revenue", "balance": 0, "is_system_default": 1, "created_at": datetime.now()},
            {"id": get_next_sequence_value("accounts"), "name": "Operating Expenses", "type": "Expense", "balance": 0, "is_system_default": 1, "created_at": datetime.now()}
        ])

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
            "role_name": role_name,
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
                "bank_accounts": list(
                    db.bank_accounts.find({"is_active": {"$ne": 0}}, {"_id": 0}).sort("label", 1)
                ),
            }
        )
    )


@app.route("/api/setup")
def api_setup_home():
    db = get_db()
    metrics = {
        "users": db.app_users.count_documents({}),
        "roles": db.roles.count_documents({}),
        "objects": db.custom_objects.count_documents({}),
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
    objects = list(db.custom_objects.find({}, {"_id": 0}).sort("plural_label", 1))
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
    if request.method == "POST":
        data = request.get_json()
        api_name = slugify_api_name(data["plural_label"])
        
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
        {"$lookup": {"from": "custom_fields", "localField": "id", "foreignField": "object_id", "as": "fields"}},
        {"$addFields": {"field_count": {"$size": "$fields"}}},
        {"$project": {"_id": 0, "fields": 0}},
        {"$sort": {"is_standard": -1, "plural_label": 1}}
    ]))
    return jsonify(json_ready({"objects": objects}))


@app.route("/api/setup/objects/<string:api_name>", methods=["GET"])
def api_setup_object_detail(api_name):
    db = get_db()
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
        customer_id = get_next_sequence_value("customers")
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        
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
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge all other dynamic custom or standard fields
        for k, v in data.items():
            if k not in insert_data:
                insert_data[k] = v
                
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        update_data = {
            "company_name": data.get("company_name"),
            "contact_name": data.get("contact_name"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "industry": data.get("industry"),
            "status": data.get("status"),
            "notes": data.get("notes"),
            "billing_address": data.get("billing_address"),
            "updated_at": datetime.now(),
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge all other dynamic fields
        for k, v in data.items():
            if k not in update_data and k != "id" and k != "created_at":
                update_data[k] = v
                
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        
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
        for k, v in data.items():
            if k not in insert_data:
                insert_data[k] = v
                
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
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
        for k, v in data.items():
            if k not in update_data and k != "id" and k != "created_at":
                update_data[k] = v
                
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        
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
        for k, v in data.items():
            if k not in insert_data:
                insert_data[k] = v
                
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
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
        for k, v in data.items():
            if k not in update_data and k != "id" and k != "created_at":
                update_data[k] = v
                
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
        vendor_id = get_next_sequence_value("vendors")
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        
        insert_data = {
            "id": vendor_id,
            "name": data.get("name"),
            "contact_person": data.get("contact_person"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "category": data.get("category"),
            "notes": data.get("notes"),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        for k, v in data.items():
            if k not in insert_data:
                insert_data[k] = v
                
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        update_data = {
            "name": data.get("name"),
            "contact_person": data.get("contact_person"),
            "email": data.get("email"),
            "phone": data.get("phone"),
            "category": data.get("category"),
            "notes": data.get("notes"),
            "updated_at": datetime.now(),
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        }
        # Merge other dynamic custom fields
        for k, v in data.items():
            if k not in update_data and k != "id" and k != "created_at":
                update_data[k] = v
                
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
            
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        insert_data = {
            "id": transaction_id,
            "account_id": int(data.get("account_id")) if data.get("account_id") else None,
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "vendor_id": int(data.get("vendor_id")) if data.get("vendor_id") else None,
            "project_id": int(data.get("project_id")) if data.get("project_id") else None,
            "transaction_date": date_val,
            "date": date_val,
            "description": data.get("description"),
            "type": data.get("type", "Income"),
            "amount": amount,
            "currency": data.get("currency", "USD"),
            "reference": data.get("reference"),
            "category": data.get("category"),
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
        db.transactions.insert_one(insert_data)
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
        {"$addFields": {
            "account_name": "$account.name",
            "customer_name": "$customer.company_name",
            "vendor_name": "$vendor.name",
            "project_name": "$project.project_name",
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]}
        }},
        {"$project": {"account": 0, "customer": 0, "vendor": 0, "project": 0, "_id": 0}},
        {"$sort": {"transaction_date": -1}}
    ]))
    return jsonify(json_ready({"transactions": transactions}))

@app.route("/api/finance/transactions/<transaction_id>", methods=["GET", "PUT"])
def api_finance_transaction_detail(transaction_id):
    require_finance_access()
    db = get_db()
    
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
            
        old_tx = db.transactions.find_one({"id": transaction_id})
        db.transactions.update_one(
            {"id": transaction_id},
            {"$set": {
                "account_id": int(data.get("account_id")) if data.get("account_id") else None,
                "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
                "vendor_id": int(data.get("vendor_id")) if data.get("vendor_id") else None,
                "project_id": int(data.get("project_id")) if data.get("project_id") else None,
                "transaction_date": date_val,
                "date": date_val,
                "description": data.get("description"),
                "type": data.get("type"),
                "amount": amount,
                "currency": data.get("currency"),
                "reference": data.get("reference"),
                "category": data.get("category"),
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
        new_tx = db.transactions.find_one({"id": transaction_id})
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
        {"$addFields": {
            "account_name": "$account.name",
            "customer_name": "$customer.company_name",
            "vendor_name": "$vendor.name",
            "project_name": "$project.project_name",
            "transaction_date": {"$ifNull": ["$transaction_date", "$date"]}
        }},
        {"$project": {"account": 0, "customer": 0, "vendor": 0, "project": 0, "_id": 0}}
    ]))
    if not transactions:
        abort(404)
        
    return jsonify(json_ready({
        "transaction": transactions[0],
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
        
    # 2. Find and delete synced treasury revenue and its payouts immediately
    rev = db.treasury_revenue.find_one({"transaction_id": transaction_id})
    if rev:
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
            
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        insert_data = {
            "id": invoice_id,
            "invoice_number": invoice_number,
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "project_id": int(data.get("project_id")) if data.get("project_id") else None,
            "issue_date": issue_date,
            "due_date": data.get("due_date"),
            "subtotal": float(data.get("subtotal", 0)),
            "tax_rate": float(data.get("tax_rate", 0)),
            "tax_amount": float(data.get("tax_amount", 0)),
            "total_amount": float(data.get("total_amount", 0)),
            "currency": data.get("currency", "USD"),
            "status": data.get("status", "Draft"),
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
        actor = get_current_user()
        actor_id = actor["id"] if actor else None
        actor_name = actor.get("full_name", "Unknown") if actor else "System"
        issue_date = data.get("invoice_date") or data.get("issue_date")
        if not issue_date:
            issue_date = datetime.now().strftime("%Y-%m-%d")
            
        old_inv = db.invoices.find_one({"id": invoice_id})
        inv_number = data.get("invoice_number") or (old_inv.get("invoice_number") if old_inv else None)
        bank_account_id = int(data["bank_account_id"]) if data.get("bank_account_id") else None
        db.invoices.update_one(
            {"id": invoice_id},
            {"$set": {
                "invoice_number": data.get("invoice_number"),
                "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
                "project_id": int(data.get("project_id")) if data.get("project_id") else None,
                "issue_date": issue_date,
                "due_date": data.get("due_date"),
                "subtotal": float(data.get("subtotal")) if data.get("subtotal") is not None else 0.0,
                "tax_rate": float(data.get("tax_rate")) if data.get("tax_rate") is not None else 0.0,
                "tax_amount": float(data.get("tax_amount")) if data.get("tax_amount") is not None else 0.0,
                "total_amount": float(data.get("total_amount")) if data.get("total_amount") is not None else 0.0,
                "currency": data.get("currency"),
                "status": data.get("status"),
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
        {"$match": {"payout_type": "Reserve Expense", **reserve_balance_match}},
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
        {"$match": {"payout_type": {"$in": ["Reserve Fund", "Reserve Expense"]}, **reserve_balance_match}},
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
        
    payout_id = get_next_sequence_value("treasury_payouts")
    db.treasury_payouts.insert_one({
        "id": payout_id,
        "payout_type": "Reserve Expense",
        "entity_id": None,
        "amount": amount,
        "status": "Paid",
        "payout_date": expense_date,
        "description": desc,
        "created_at": datetime.now()
    })
    
    log_treasury_action(user["id"], "Reserve Expense Recorded", f"Deducted {amount} from Reserve Fund: {desc}")
    return jsonify({"ok": True})

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
        db.treasury_stakeholders.insert_one({
            "id": sid,
            "name": data.get("name"),
            "payout_percentage": payout_pct,
            "equity_percentage": payout_pct, # backward compatible
            "payment_details": data.get("payment_details", ""),
            "is_active": data.get("is_active", True),
            "created_at": datetime.now()
        })
        log_treasury_action(
            user["id"],
            "Added Company Owner",
            format_stakeholder_audit_details(None, data),
        )
        return jsonify({"ok": True})
        
    stakeholders = list(db.treasury_stakeholders.find({}, {"_id": 0}))
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
    db.treasury_stakeholders.update_one(
        {"id": sid},
        {"$set": {
            "name": data.get("name"),
            "payout_percentage": payout_pct,
            "equity_percentage": payout_pct, # backward compatible
            "payment_details": data.get("payment_details", ""),
            "is_active": data.get("is_active", True)
        }}
    )
    log_treasury_action(
        user["id"],
        "Updated Company Owner",
        format_stakeholder_audit_details(old_doc, data),
    )
    return jsonify({"ok": True})

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
        
        reserve_percentage = float(data.get("reserve_percentage", 20.0))
        channel_partner_id = data.get("channel_partner_id")
        if channel_partner_id: channel_partner_id = int(channel_partner_id)
        
        description = data.get("description", "")
        
        # Calculate Splits
        reserve_amount = amount * (reserve_percentage / 100.0)
        
        partner_commission = 0.0
        if channel_partner_id:
            partner = db.treasury_partners.find_one({"id": channel_partner_id})
            if partner:
                val = float(partner.get("commission_value", 0))
                if partner.get("commission_type") == "Percentage":
                    partner_commission = amount * (val / 100.0)
                else:
                    partner_commission = val
                    
        stakeholder_total = max(0.0, amount - reserve_amount - partner_commission)
        
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
        
    purge_unsettled_revenue_payouts(db)
    normalize_stakeholder_flow_payouts(db)

    # Auto-sync ledger transactions from db.transactions (only active ones, not Reversed)
    all_txns = list(db.transactions.find({"status": {"$ne": "Reversed"}}))
    
    for t in all_txns:
        existing = db.treasury_revenue.find_one({"transaction_id": t["id"]})
        if not existing:
            amount = float(t.get("amount") or t.get("total_amount") or 0.0)
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
                reserve_percentage = 20.0
                reserve_amount = amount * 0.20
                partner_commission = 0.0
                stakeholder_total = amount - reserve_amount
                revenue_type = "Sales Income"
                
            entry_date = t.get("transaction_date") or t.get("date") or datetime.now().strftime("%Y-%m-%d")
            
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
    
    reserve_percentage = float(data.get("reserve_percentage", 20.0))
    channel_partner_id = data.get("channel_partner_id")
    if channel_partner_id: channel_partner_id = int(channel_partner_id)
    
    partner_commission_percentage = float(data.get("partner_commission_percentage", 0.0)) if channel_partner_id else 0.0
    stk_splits = data.get("stakeholders", [])
    stakeholder_pct_sum = sum(float(s.get("percentage", 0)) for s in stk_splits)
    total_split_pct = reserve_percentage + partner_commission_percentage + stakeholder_pct_sum
    if abs(total_split_pct - 100.0) > 0.01:
        return jsonify({"error": "Split percentages must sum to exactly 100% before settlement."}), 400

    partner_commission = amount * (partner_commission_percentage / 100.0) if channel_partner_id else 0.0
    
    reserve_amount = amount * (reserve_percentage / 100.0)
    stakeholder_total = amount - reserve_amount - partner_commission
    
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
    
    # Re-insert payouts
    # 1. Reserve split
    is_neg = reserve_amount < 0
    db.treasury_payouts.insert_one({
        "id": get_next_sequence_value("treasury_payouts"),
        "revenue_id": revenue_id,
        "payout_type": "Reserve Expense" if is_neg else "Reserve Fund",
        "amount": abs(reserve_amount),
        "status": "Paid" if is_neg else "Completed",
        "payout_date": entry_date,
        "description": f"Reserve fund split allocation for REV-{revenue_id}",
        "created_at": datetime.now()
    })
    
    # 2. Channel Partner Commission payout
    if channel_partner_id and abs(partner_commission) > 0:
        db.treasury_payouts.insert_one({
            "id": get_next_sequence_value("treasury_payouts"),
            "revenue_id": revenue_id,
            "payout_type": "Channel Partner",
            "partner_id": channel_partner_id,
            "amount": abs(partner_commission),
            "status": "Pending",
            "payout_date": entry_date,
            "description": f"Commission payout for Channel Partner ID {channel_partner_id}",
            "created_at": datetime.now()
        })
        
    # 3. Owner splits — contributions on expenses, earnings on income
    is_company_expense = amount < 0
    for stk_split in stk_splits:
        sid = int(stk_split["id"])
        pct = float(stk_split.get("percentage", 0))
        share = amount * (pct / 100.0)
        if abs(share) <= 0:
            continue
        stk = db.treasury_stakeholders.find_one({"id": sid}, {"_id": 0, "name": 1})
        stk_name = stk.get("name") if stk else f"Owner ID {sid}"
        if is_company_expense:
            db.treasury_payouts.insert_one({
                "id": get_next_sequence_value("treasury_payouts"),
                "revenue_id": revenue_id,
                "payout_type": "Stakeholder Contribution",
                "stakeholder_id": sid,
                "amount": abs(share),
                "status": "Received",
                "payout_date": entry_date,
                "description": f"{stk_name} contributed {_format_pct(pct)}% (₹{abs(share):.2f}) toward company expense REV-{revenue_id}",
                "created_at": datetime.now()
            })
        else:
            db.treasury_payouts.insert_one({
                "id": get_next_sequence_value("treasury_payouts"),
                "revenue_id": revenue_id,
                "payout_type": "Stakeholder",
                "stakeholder_id": sid,
                "amount": abs(share),
                "status": "Pending",
                "payout_date": entry_date,
                "description": f"{stk_name} earning {_format_pct(pct)}% (₹{abs(share):.2f}) from REV-{revenue_id}",
                "created_at": datetime.now()
            })
            
    entry_kind = "company expense (owner contributions)" if is_company_expense else "shared revenue (owner earnings)"
    log_treasury_action(
        user["id"],
        "Revenue Settled",
        f"Finalized 100% split for REV-{revenue_id} as {entry_kind}. Entry is locked.",
    )
    return jsonify({"ok": True, "is_settled": True})

@app.route("/api/treasury/payouts", methods=["GET"])
def api_treasury_payouts():
    user = require_treasury_access()
    db = get_db()
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
