import json
import os
import re
from contextlib import contextmanager
from datetime import date, datetime
from decimal import Decimal

import pymongo
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
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


CUSTOMER_STATUSES = ["Lead", "Active", "Inactive"]
OPPORTUNITY_STAGES = ["Draft", "Discussion", "Contractual negotiations", "DA Signed", "Lost to competitor", "Rejected by SC", "Lost"]
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
            "created_at": datetime.now()
        })
    else:
        # Ensure password is set
        admin = db.app_users.find_one({"email": "system.administrator@swarajyaconsultancy.in"})
        if not admin.get("password_hash"):
            db.app_users.update_one({"_id": admin["_id"]}, {"$set": {"password_hash": generate_password_hash("change123")}})

    # Indexes
    db.app_users.create_index("email", unique=True)
    db.invoices.create_index("invoice_number", unique=True)
    db.treasury_revenue.create_index("revenue_id", unique=True)
    db.custom_objects.create_index("api_name", unique=True)


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
        
        user_data = {
            "id": user["id"],
            "full_name": user.get("full_name"),
            "email": user.get("email"),
            "role_name": role_name,
            "has_treasury_access": user.get("has_treasury_access", 0),
            "has_finance_access": user.get("has_finance_access", 0)
        }
        return jsonify({"user": user_data})
        
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    session.clear()
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


def dashboard_payload():
    db = get_db()
    
    metrics = {
        "customers": db.customers.count_documents({}),
        "open_opportunities": db.opportunities.count_documents({"stage": {"$nin": ["Won", "Lost"]}}),
        "pipeline_values": list(db.opportunities.aggregate([
            {"$match": {"stage": {"$nin": ["Won", "Lost"]}}},
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


@app.route("/api/setup/users", methods=["GET", "POST"])
def api_setup_users():
    db = get_db()
    if request.method == "POST":
        data = request.get_json()
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
            "created_at": datetime.now()
        })
        return jsonify({"id": user_id})
        
    users = list(db.app_users.aggregate([
        {"$lookup": {"from": "roles", "localField": "role_id", "foreignField": "id", "as": "role"}},
        {"$unwind": {"path": "$role", "preserveNullAndEmptyArrays": True}},
        {"$project": {"_id": 0, "password_hash": 0}},
        {"$addFields": {"role_name": "$role.name"}},
        {"$project": {"role": 0}},
        {"$sort": {"created_at": -1}}
    ]))
    return jsonify(json_ready({"users": users}))


@app.route("/api/setup/users/<int:user_id>", methods=["GET", "PUT"])
def api_setup_user(user_id):
    db = get_db()
    user = db.app_users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        abort(404)
        
    if request.method == "PUT":
        data = request.get_json()
        update_data = {
            "full_name": data["full_name"],
            "email": data["email"],
            "role_id": data.get("role_id") or None,
            "is_active": data.get("is_active", True),
            "has_treasury_access": 1 if data.get("has_treasury_access") else 0,
            "has_finance_access": 1 if data.get("has_finance_access") else 0
        }
        if data.get("password"):
            update_data["password_hash"] = generate_password_hash(data["password"])
            
        db.app_users.update_one({"id": user_id}, {"$set": update_data})
        return jsonify({"success": True})
        
    return jsonify(json_ready(user))


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
        db.custom_objects.insert_one({
            "id": object_id,
            "label": data["label"],
            "plural_label": data["plural_label"],
            "api_name": api_name,
            "is_standard": 0,
            "storage_table": None,
            "description": data.get("description"),
            "created_at": datetime.now()
        })
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
    db.custom_fields.insert_one({
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
    })
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
        return jsonify({"success": True})
        
    data = request.get_json()
    update_data = {
        "label": data["label"],
        "field_type": data["field_type"],
        "picklist_options": data.get("picklist_options"),
        "is_required": 1 if data.get("is_required") else 0
    }
    db.custom_fields.update_one({"id": field_id}, {"$set": update_data})
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
    db.custom_objects.update_one(
        {"id": object_id},
        {"$set": {
            "label": data["label"],
            "plural_label": data["plural_label"],
            "description": data.get("description")
        }}
    )
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
        fields = list(db.custom_fields.find({"object_id": customer_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
                
        db.customers.update_one(
            {"id": customer_id},
            {"$set": update_data}
        )
        return jsonify({"success": True})
        
    # Fetch related
    opportunities = list(db.opportunities.find({"customer_id": customer_id}, {"_id": 0}))
    projects = list(db.projects.find({"customer_id": customer_id}, {"_id": 0}))
    
    # Fetch fields configured for the Customer object
    customer_obj = db.custom_objects.find_one({"api_name": "customers"})
    fields = []
    if customer_obj:
        fields = list(db.custom_fields.find({"object_id": customer_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
        
        insert_data = {
            "id": opportunity_id,
            "title": data.get("title"),
            "customer_id": int(data.get("customer_id")) if data.get("customer_id") else None,
            "country": data.get("country"),
            "opportunity_number": data.get("opportunity_number"),
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
        fields = list(db.custom_fields.find({"object_id": opp_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
            "country": data.get("country"),
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
                
        db.opportunities.update_one(
            {"id": opportunity_id},
            {"$set": update_data}
        )
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
        fields = list(db.custom_fields.find({"object_id": opp_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
        fields = list(db.custom_fields.find({"object_id": proj_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
                
        db.projects.update_one(
            {"id": project_id},
            {"$set": update_data}
        )
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
        fields = list(db.custom_fields.find({"object_id": proj_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
        
        vendor = db.vendors.find_one({"id": vendor_id}, {"_id": 0})
        return jsonify(json_ready({"vendor": vendor}))
        
    vendors = list(db.vendors.find({}, {"_id": 0}).sort("created_at", -1))
    
    # Fetch fields configured for the Vendor object
    vendor_obj = db.custom_objects.find_one({"api_name": "vendors"})
    fields = []
    if vendor_obj:
        fields = list(db.custom_fields.find({"object_id": vendor_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
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
                
        db.vendors.update_one(
            {"id": vendor_id},
            {"$set": update_data}
        )
        return jsonify({"success": True})
        
    # Fetch fields configured for the Vendor object
    vendor_obj = db.custom_objects.find_one({"api_name": "vendors"})
    fields = []
    if vendor_obj:
        fields = list(db.custom_fields.find({"object_id": vendor_obj["id"]}, {"_id": 0}).sort("is_native", -1))
        
    return jsonify(json_ready({
        "vendor": vendor,
        "fields": fields
    }))


@app.route("/api/finance")
def api_finance_dashboard():
    require_finance_access()
    db = get_db()
    total_revenue = list(db.transactions.aggregate([
        {"$match": {"type": "Credit", "status": "Completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    total_revenue_val = total_revenue[0]["total"] if total_revenue else 0
    
    total_expenses = list(db.transactions.aggregate([
        {"$match": {"type": "Debit", "status": "Completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    total_expenses_val = total_expenses[0]["total"] if total_expenses else 0
    
    unpaid_invoices_count = db.invoices.count_documents({"status": {"$in": ["Draft", "Sent", "Partially Paid"]}})
    
    metrics = {
        "total_revenue": total_revenue_val,
        "total_expenses": total_expenses_val,
        "net_profit": total_revenue_val - total_expenses_val,
        "unpaid_invoices": unpaid_invoices_count,
    }
    
    recent_transactions = list(db.transactions.aggregate([
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
        transaction_id = get_next_sequence_value("transactions")
        
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
        db.transactions.insert_one({
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
        })
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

@app.route("/api/finance/transactions/<int:transaction_id>", methods=["GET", "PUT"])
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

@app.route("/api/finance/transactions/<int:transaction_id>/reverse", methods=["POST"])
def api_finance_transaction_reverse(transaction_id):
    require_finance_access()
    db = get_db()
    
    # 1. Update transaction status in db.transactions
    res = db.transactions.update_one(
        {"id": transaction_id},
        {"$set": {"status": "Reversed"}}
    )
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
        db.invoices.insert_one({
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
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "created_by_id": actor_id,
            "created_by_name": actor_name,
            "modified_by_id": actor_id,
            "modified_by_name": actor_name
        })
        
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
                "updated_at": datetime.now(),
                "modified_by_id": actor_id,
                "modified_by_name": actor_name
            }}
        )
        return jsonify({"success": True})
        
    if request.method == "DELETE":
        db.invoices.delete_one({"id": invoice_id})
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
    import json
    setting = db.system_settings.find_one({"key_name": "company_profile"})
    company_info = json.loads(setting["value"]) if setting and setting.get("value") else None
    inv_dict["company_info"] = company_info
    
    return jsonify(json_ready({"invoice": inv_dict, "items": inv_dict.get("items", [])}))

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

@app.route("/api/finance/reports/general-ledger")
def api_gl_report():
    require_finance_access()
    db = get_db()
    query = {}
    
    account_id = request.args.get("account_id")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    
    # 1. Compute opening balance of previous transactions
    opening_balance = 0.0
    if start_date:
        opening_query = {"date": {"$lt": start_date}, "status": {"$ne": "Reversed"}}
        if account_id:
            opening_query["account_id"] = int(account_id)
            
        opening_txns = list(db.transactions.find(opening_query))
        for t in opening_txns:
            amt = float(t.get("total_amount") or t.get("amount") or 0.0)
            if t.get("type") == "Income":
                opening_balance += amt
            else:
                opening_balance -= amt
                
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
    
    # 3. Calculate running balance and debit/credit columns
    entries = []
    running_balance = opening_balance
    total_credits = 0.0
    total_debits = 0.0
    
    for t in transactions:
        amt = float(t.get("total_amount") or t.get("amount") or 0.0)
        is_income = t.get("type") == "Income"
        
        debit = None
        credit = None
        
        if is_income:
            credit = amt
            total_credits += amt
            running_balance += amt
        else:
            debit = amt
            total_debits += amt
            running_balance -= amt
            
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
    # Skip exchange rates for now
    return jsonify({"success": True})

@app.route("/api/treasury/dashboard", methods=["GET"])
def api_treasury_dashboard():
    user = require_treasury_access()
    db = get_db()
    
    # 1. Total revenue
    total_rev_doc = list(db.treasury_revenue.aggregate([{"$group": {"_id": None, "total": {"$sum": "$amount"}}}]))
    total_revenue = total_rev_doc[0]["total"] if total_rev_doc else 0.0
    
    # 2. Reserve Fund Accumulated
    reserve_acc_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Reserve Fund"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    reserve_accumulated = reserve_acc_doc[0]["total"] if reserve_acc_doc else 0.0
    
    # 3. Reserve Fund Spent
    reserve_spent_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Reserve Expense"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    reserve_spent = reserve_spent_doc[0]["total"] if reserve_spent_doc else 0.0
    
    reserve_available = reserve_accumulated - reserve_spent
    
    # 4. Partner Payouts
    partner_paid_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Channel Partner", "status": "Paid"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    partner_paid = partner_paid_doc[0]["total"] if partner_paid_doc else 0.0
    
    partner_pending_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Channel Partner", "status": "Pending"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    partner_pending = partner_pending_doc[0]["total"] if partner_pending_doc else 0.0
    
    # 5. Stakeholder Payouts
    stakeholder_paid_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Stakeholder", "status": "Paid"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    stakeholder_paid = stakeholder_paid_doc[0]["total"] if stakeholder_paid_doc else 0.0
    
    stakeholder_pending_doc = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": "Stakeholder", "status": "Pending"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]))
    stakeholder_pending = stakeholder_pending_doc[0]["total"] if stakeholder_pending_doc else 0.0
    
    # 6. Recent Payouts
    recent_payouts = list(db.treasury_payouts.aggregate([
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
        "total_revenue": total_revenue,
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
    
    # 1. Fetch Stakeholders and calculate their metrics
    stk_list = []
    stakeholders = list(db.treasury_stakeholders.find({}))
    for s in stakeholders:
        sid = s.get("id")
        paid_amt = 0.0
        pending_amt = 0.0
        
        # Aggregate paid
        paid_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Paid"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if paid_doc: paid_amt = paid_doc[0]["total"]
        
        # Aggregate pending
        pending_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Pending"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if pending_doc: pending_amt = pending_doc[0]["total"]
        
        stk_list.append({
            "id": sid,
            "name": s.get("name"),
            "payout_percentage": s.get("payout_percentage"),
            "is_active": s.get("is_active"),
            "paid_amount": paid_amt,
            "pending_amount": pending_amt
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
            {"$match": {"payout_type": "Channel Partner", "partner_id": pid, "status": "Paid"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]))
        if paid_doc: paid_amt = paid_doc[0]["total"]
        
        # Aggregate pending
        pending_doc = list(db.treasury_payouts.aggregate([
            {"$match": {"payout_type": "Channel Partner", "partner_id": pid, "status": "Pending"}},
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
        
    # 3. Reserve Ledger
    reserve_ledger = list(db.treasury_payouts.aggregate([
        {"$match": {"payout_type": {"$in": ["Reserve Fund", "Reserve Expense"]}}},
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
    
    db.treasury_payouts.update_many(
        {"payout_type": "Stakeholder", "stakeholder_id": sid, "status": "Pending"},
        {"$set": {"status": "Paid"}}
    )
    
    log_treasury_action(user["id"], "Stakeholder Settled", f"Stakeholder ID {sid} pending payouts marked as Paid.")
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
        log_treasury_action(user["id"], "Added Stakeholder", f"Created stakeholder {data.get('name')}")
        return jsonify({"ok": True})
        
    stakeholders = list(db.treasury_stakeholders.find({}, {"_id": 0}))
    return jsonify(json_ready({"stakeholders": stakeholders}))

@app.route("/api/treasury/stakeholders/<int:sid>", methods=["PUT"])
def api_treasury_stakeholder_detail(sid):
    user = require_treasury_access()
    db = get_db()
    data = request.get_json() or {}
    
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
    log_treasury_action(user["id"], "Updated Stakeholder", f"Updated stakeholder ID {sid}")
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
            "created_at": datetime.now()
        })
        
        # Insert payouts
        # 1. Reserve Fund allocation
        db.treasury_payouts.insert_one({
            "id": get_next_sequence_value("treasury_payouts"),
            "revenue_id": rev_id,
            "payout_type": "Reserve Fund",
            "amount": reserve_amount,
            "status": "Completed",
            "payout_date": entry_date,
            "description": f"Reserve fund split allocation for REV-{rev_id}",
            "created_at": datetime.now()
        })
        
        # 2. Channel Partner Commission payout
        if channel_partner_id and partner_commission > 0:
            db.treasury_payouts.insert_one({
                "id": get_next_sequence_value("treasury_payouts"),
                "revenue_id": rev_id,
                "payout_type": "Channel Partner",
                "partner_id": channel_partner_id,
                "amount": partner_commission,
                "status": "Pending",
                "payout_date": entry_date,
                "description": f"Commission payout for Channel Partner ID {channel_partner_id}",
                "created_at": datetime.now()
            })
            
        # 3. Active Stakeholder distributions
        active_stks = list(db.treasury_stakeholders.find({"is_active": True}))
        for s in active_stks:
            pct = float(s.get("payout_percentage", 0))
            share = stakeholder_total * (pct / 100.0)
            if share > 0:
                db.treasury_payouts.insert_one({
                    "id": get_next_sequence_value("treasury_payouts"),
                    "revenue_id": rev_id,
                    "payout_type": "Stakeholder",
                    "stakeholder_id": s.get("id"),
                    "amount": share,
                    "status": "Pending",
                    "payout_date": entry_date,
                    "description": f"Equity distribution share ({pct}%) for Stakeholder {s.get('name')}",
                    "created_at": datetime.now()
                })
                
        log_treasury_action(user["id"], "Logged Revenue", f"Recorded shared revenue split of {amount} as REV-{rev_id}.")
        return jsonify({"ok": True})
        
    # Auto-sync ledger transactions from db.transactions (only active ones, not Reversed)
    all_txns = list(db.transactions.find({"status": {"$ne": "Reversed"}}))
    active_stks = list(db.treasury_stakeholders.find({"is_active": True}))
    
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
                "created_at": datetime.now()
            })
            
            # Payouts
            # 1. Reserve split
            db.treasury_payouts.insert_one({
                "id": get_next_sequence_value("treasury_payouts"),
                "revenue_id": rev_id,
                "payout_type": "Reserve Expense" if is_expense else "Reserve Fund",
                "amount": abs(reserve_amount),
                "status": "Paid" if is_expense else "Completed",
                "payout_date": entry_date,
                "description": f"Reserve fund split allocation for transaction #{t['id']}",
                "created_at": datetime.now()
            })
            
            # 2. Stakeholder split (only for Income)
            if not is_expense:
                for s in active_stks:
                    pct = float(s.get("payout_percentage", 0))
                    share = stakeholder_total * (pct / 100.0)
                    if share > 0:
                        db.treasury_payouts.insert_one({
                            "id": get_next_sequence_value("treasury_payouts"),
                            "revenue_id": rev_id,
                            "payout_type": "Stakeholder",
                            "stakeholder_id": s.get("id"),
                            "amount": share,
                            "status": "Pending",
                            "payout_date": entry_date,
                            "description": f"Equity distribution share ({pct}%) for Stakeholder {s.get('name')}",
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
        
    amount = float(rev.get("amount", 0.0))
    entry_date = rev.get("entry_date", datetime.now().strftime("%Y-%m-%d"))
    
    reserve_percentage = float(data.get("reserve_percentage", 20.0))
    channel_partner_id = data.get("channel_partner_id")
    if channel_partner_id: channel_partner_id = int(channel_partner_id)
    
    partner_commission_percentage = float(data.get("partner_commission_percentage", 0.0))
    partner_commission = amount * (partner_commission_percentage / 100.0) if channel_partner_id else 0.0
    
    reserve_amount = amount * (reserve_percentage / 100.0)
    stakeholder_total = amount - reserve_amount - partner_commission
    
    # Update revenue document
    db.treasury_revenue.update_one(
        {"id": revenue_id},
        {"$set": {
            "reserve_percentage": reserve_percentage,
            "reserve_amount": reserve_amount,
            "channel_partner_id": channel_partner_id,
            "partner_commission": partner_commission,
            "stakeholder_total": stakeholder_total
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
        "description": f"Reserve fund split allocation for REV-{revenue_id} (Updated)",
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
            "description": f"Commission payout for Channel Partner ID {channel_partner_id} (Updated)",
            "created_at": datetime.now()
        })
        
    # 3. Custom Stakeholder distributions from payload
    stk_splits = data.get("stakeholders", [])
    for stk_split in stk_splits:
        sid = int(stk_split["id"])
        pct = float(stk_split.get("percentage", 0))
        share = amount * (pct / 100.0)
        if abs(share) > 0:
            db.treasury_payouts.insert_one({
                "id": get_next_sequence_value("treasury_payouts"),
                "revenue_id": revenue_id,
                "payout_type": "Stakeholder",
                "stakeholder_id": sid,
                "amount": abs(share),
                "status": "Pending",
                "payout_date": entry_date,
                "description": f"Equity distribution share ({pct}%) for Stakeholder ID {sid} (Updated)",
                "created_at": datetime.now()
            })
            
    log_treasury_action(user["id"], "Updated Payout Splits", f"Recalculated split allocations for REV-{revenue_id}.")
    return jsonify({"ok": True})

@app.route("/api/treasury/payouts", methods=["GET"])
def api_treasury_payouts():
    user = require_treasury_access()
    db = get_db()
    
    payouts = list(db.treasury_payouts.aggregate([
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

if __name__ == "__main__":
    app.run(debug=True)
