import os
import re
import smtplib
import threading
from datetime import datetime, date, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import Blueprint, jsonify, request, session, abort
import pymongo

task_bp = Blueprint("task_bp", __name__)

DEFAULT_TASK_TYPES = [
    {"name": "Development", "is_active": True, "color": "#2563eb"},
    {"name": "Bug Fix", "is_active": True, "color": "#dc2626"},
    {"name": "Client Change Request", "is_active": True, "color": "#d97706"},
    {"name": "Deployment", "is_active": True, "color": "#7c3aed"},
    {"name": "Testing / QA", "is_active": True, "color": "#059669"},
    {"name": "Configuration", "is_active": True, "color": "#4b5563"},
    {"name": "Documentation", "is_active": True, "color": "#0284c7"},
    {"name": "Client Support", "is_active": True, "color": "#ea580c"},
    {"name": "Maintenance", "is_active": True, "color": "#4f46e5"},
    {"name": "Research", "is_active": True, "color": "#0891b2"},
    {"name": "Internal Operations", "is_active": True, "color": "#16a34a"},
    {"name": "Other", "is_active": True, "color": "#64748b"}
]

DEFAULT_CATEGORIES = [
    "Client Delivery",
    "Engineering & Tech",
    "Infrastructure & Cloud",
    "Quality Assurance",
    "Internal Operations",
    "Customer Support",
    "Research & Planning"
]

DEFAULT_SLA_POLICIES = [
    {"priority": "Critical", "response_hours": 1, "resolution_hours": 8},
    {"priority": "High", "response_hours": 4, "resolution_hours": 24},
    {"priority": "Medium", "response_hours": 8, "resolution_hours": 48},
    {"priority": "Low", "response_hours": 24, "resolution_hours": 120}
]

DEFAULT_ESCALATION_RULES = [
    {"level": 1, "trigger_hours_overdue": 24, "notify_creator": True, "notify_assignee": True, "notify_manager": True, "is_active": True},
    {"level": 2, "trigger_hours_overdue": 48, "notify_creator": True, "notify_assignee": True, "notify_manager": True, "is_high_priority_only": True, "is_active": True}
]

def get_db():
    from app import get_db as app_get_db
    return app_get_db()

def get_next_sequence_value(sequence_name):
    from app import get_next_sequence_value as app_get_next_seq
    return app_get_next_seq(sequence_name)

def json_ready(data):
    from app import json_ready as app_json_ready
    return app_json_ready(data)

def get_current_user():
    from app import get_current_user as app_get_current_user
    return app_get_current_user()

def require_current_user():
    user = get_current_user()
    if not user:
        abort(401)
    return user

def ensure_task_settings():
    db = get_db()
    existing = db.task_settings.find_one({"id": "default"})
    if not existing:
        settings_doc = {
            "id": "default",
            "task_types": DEFAULT_TASK_TYPES,
            "categories": DEFAULT_CATEGORIES,
            "sla_policies": DEFAULT_SLA_POLICIES,
            "escalation_rules": DEFAULT_ESCALATION_RULES,
            "smtp_settings": {
                "host": os.getenv("SMTP_HOST", ""),
                "port": int(os.getenv("SMTP_PORT", 587)),
                "username": os.getenv("SMTP_USER", ""),
                "password": os.getenv("SMTP_PASSWORD", ""),
                "use_tls": True,
                "use_ssl": False,
                "from_email": os.getenv("SMTP_FROM", "notifications@swarajyaconsultancy.in"),
                "from_name": "Swarajya CRM",
                "is_enabled": bool(os.getenv("SMTP_HOST"))
            },
            "notification_preferences": {
                "notify_assignment": True,
                "notify_reassignment": True,
                "notify_status_change": True,
                "notify_due_date_change": True,
                "notify_comments": True,
                "notify_review": True,
                "notify_escalation": True
            },
            "created_at": datetime.now(),
            "updated_at": datetime.now()
        }
        db.task_settings.insert_one(settings_doc)
        return settings_doc
    return existing

# ─────────────────────────────────────────────────────────────────────────────
# Email Notification Dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def _dispatch_email_async(to_email, to_name, subject, body_text, notification_id):
    db = get_db()
    settings = db.task_settings.find_one({"id": "default"}) or {}
    smtp_cfg = settings.get("smtp_settings", {})

    host = smtp_cfg.get("host") or os.getenv("SMTP_HOST")
    port = int(smtp_cfg.get("port") or os.getenv("SMTP_PORT", 587))
    user = smtp_cfg.get("username") or os.getenv("SMTP_USER")
    password = smtp_cfg.get("password") or os.getenv("SMTP_PASSWORD")
    from_email = smtp_cfg.get("from_email") or os.getenv("SMTP_FROM") or "notifications@swarajyaconsultancy.in"
    from_name = smtp_cfg.get("from_name", "Swarajya CRM")
    is_enabled = smtp_cfg.get("is_enabled", False) or bool(host)

    if not is_enabled or not host or not to_email:
        status_note = "Logged (SMTP not enabled)" if not host else "Missing recipient email"
        db.task_notifications.update_one(
            {"id": notification_id},
            {"$set": {"status": status_note, "updated_at": datetime.now()}}
        )
        return

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = f"{to_name} <{to_email}>"
        msg.attach(MIMEText(body_text, "plain"))

        if smtp_cfg.get("use_ssl", False):
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            if smtp_cfg.get("use_tls", True):
                server.starttls()

        if user and password:
            server.login(user, password)

        server.sendmail(from_email, [to_email], msg.as_string())
        server.quit()

        db.task_notifications.update_one(
            {"id": notification_id},
            {"$set": {"status": "Sent", "sent_at": datetime.now(), "updated_at": datetime.now()}}
        )
    except Exception as e:
        db.task_notifications.update_one(
            {"id": notification_id},
            {"$set": {"status": "Failed", "error": str(e), "updated_at": datetime.now()}}
        )

def send_task_notification(task, event_type, recipient_user, sender_user, extra=None):
    if not recipient_user:
        return None

    db = get_db()
    # User specific requirement #28:
    # "In user setup add notification email field, so if we assign any task then mail notification shuld hits on that mail
    # i dont want user should receive notification on swarajya mail id"
    recipient_email = (recipient_user.get("notification_email") or "").strip()
    if not recipient_email:
        recipient_email = (recipient_user.get("email") or "").strip()

    recipient_name = recipient_user.get("full_name") or "Team Member"
    sender_name = sender_user.get("full_name") if sender_user else "System"

    frontend_base = os.getenv("FRONTEND_URL", "http://127.0.0.1:5173").rstrip("/")
    task_url = f"{frontend_base}/tasks/{task.get('id')}"

    task_number = task.get("task_number") or f"TASK-{task.get('id')}"
    title = task.get("title", "Untitled Task")

    subject = f"[CRM] New Task Assigned: {task_number} - {title}"
    body = (
        f"Hello {recipient_name},\n\n"
        f"A new task has been assigned to you.\n\n"
        f"Task ID: {task_number}\n"
        f"Title: {title}\n"
        f"Description: {task.get('description') or 'N/A'}\n"
        f"Priority: {task.get('priority', 'Medium')}\n"
        f"Status: {task.get('status', 'To Do')}\n"
        f"Assigned By: {sender_name}\n"
        f"Client: {task.get('customer_name') or 'N/A'}\n"
        f"Project: {task.get('project_name') or 'N/A'}\n"
        f"Environment: {task.get('environment') or 'N/A'}\n"
        f"Start Date: {task.get('start_date') or 'N/A'}\n"
        f"Due Date: {task.get('due_date')} {task.get('due_time') or ''}\n\n"
        f"Please review the task and update its status as you begin work.\n\n"
        f"View Task: {task_url}\n\n"
        f"Regards,\n"
        f"Swarajya Consultancy Team"
    )

    if event_type == "reassignment":
        subject = f"[CRM] Task Reassigned: {task_number} - {title}"
        body = (
            f"Hello {recipient_name},\n\n"
            f"A task has been reassigned to you by {sender_name}.\n\n"
            f"Task ID: {task_number}\n"
            f"Title: {title}\n"
            f"Priority: {task.get('priority', 'Medium')}\n"
            f"Due Date: {task.get('due_date')} {task.get('due_time') or ''}\n\n"
            f"View Task: {task_url}\n\n"
            f"Regards,\nSwarajya Consultancy Team"
        )
    elif event_type == "status_change":
        subject = f"[CRM] Task Status Updated: {task_number} is now {task.get('status')}"
        body = (
            f"Hello {recipient_name},\n\n"
            f"The status of task {task_number} has been updated to '{task.get('status')}' by {sender_name}.\n\n"
            f"Title: {title}\n"
            f"Updated Status: {task.get('status')}\n"
            f"View Task: {task_url}\n\n"
            f"Regards,\nSwarajya Consultancy Team"
        )
    elif event_type == "escalation":
        subject = f"[URGENT] Task Escalation: {task_number} is Overdue!"
        body = (
            f"Hello {recipient_name},\n\n"
            f"This is an automated escalation alert for task {task_number}.\n\n"
            f"Title: {title}\n"
            f"Priority: {task.get('priority')}\n"
            f"Assignee: {task.get('assignee_name')}\n"
            f"Due Date: {task.get('due_date')}\n"
            f"Current Status: {task.get('status')}\n\n"
            f"Please take immediate action to resolve or unblock this work.\n\n"
            f"View Task: {task_url}\n\n"
            f"Regards,\nCRM Escalation Engine"
        )
    elif event_type == "comment":
        subject = f"[CRM] New Comment on Task {task_number}: {title}"
        body = (
            f"Hello {recipient_name},\n\n"
            f"{sender_name} commented on task {task_number}:\n\n"
            f"\"{extra.get('comment_text', '')}\"\n\n"
            f"View Task: {task_url}\n\n"
            f"Regards,\nSwarajya Consultancy Team"
        )

    notification_id = get_next_sequence_value("task_notifications")
    notif_doc = {
        "id": notification_id,
        "task_id": task["id"],
        "task_number": task_number,
        "event_type": event_type,
        "recipient_user_id": recipient_user.get("id"),
        "recipient_name": recipient_name,
        "recipient_email": recipient_email,
        "subject": subject,
        "body": body,
        "status": "Pending",
        "created_at": datetime.now()
    }
    db.task_notifications.insert_one(notif_doc)

    # Spawn async delivery
    threading.Thread(
        target=_dispatch_email_async,
        args=(recipient_email, recipient_name, subject, body, notification_id),
        daemon=True
    ).start()

    return notification_id

# ─────────────────────────────────────────────────────────────────────────────
# Task Routes
# ─────────────────────────────────────────────────────────────────────────────

@task_bp.route("/api/tasks", methods=["GET"])
def api_tasks_list():
    user = require_current_user()
    db = get_db()
    ensure_task_settings()

    tab = request.args.get("tab", "all")
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "").strip()
    priority = request.args.get("priority", "").strip()
    task_type = request.args.get("task_type", "").strip()
    assignee_id = request.args.get("assignee_id", "").strip()
    customer_id = request.args.get("customer_id", "").strip()
    project_id = request.args.get("project_id", "").strip()
    is_overdue = request.args.get("is_overdue", "").strip().lower() == "true"

    page = max(1, int(request.args.get("page", 1)))
    limit = max(1, min(100, int(request.args.get("limit", 25))))

    query = {}

    if tab == "my":
        query["assignee_id"] = user["id"]
    elif tab == "assigned_by_me":
        query["creator_user_id"] = user["id"]
    elif tab == "escalations":
        query["$or"] = [
            {"is_escalated": True},
            {"sla_status": "Breached"},
            {"priority": "Critical", "status": {"$nin": ["Completed", "Cancelled"]}}
        ]

    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority
    if task_type:
        query["task_type"] = task_type
    if assignee_id and assignee_id.isdigit():
        query["assignee_id"] = int(assignee_id)
    if customer_id and customer_id.isdigit():
        query["customer_id"] = int(customer_id)
    if project_id and project_id.isdigit():
        query["project_id"] = int(project_id)

    today_str = date.today().strftime("%Y-%m-%d")
    if is_overdue:
        query["due_date"] = {"$lt": today_str}
        query["status"] = {"$nin": ["Completed", "Cancelled"]}

    if search:
        regex = {"$regex": re.escape(search), "$options": "i"}
        query["$or"] = [
            {"task_number": regex},
            {"title": regex},
            {"description": regex},
            {"assignee_name": regex},
            {"customer_name": regex},
            {"project_name": regex}
        ]

    total_count = db.tasks.count_documents(query)
    skip = (page - 1) * limit

    cursor = db.tasks.find(query, {"_id": 0}).sort([("created_at", pymongo.DESCENDING)]).skip(skip).limit(limit)
    tasks = list(cursor)

    # Attach overdue flag
    for t in tasks:
        if t.get("due_date") and t.get("status") not in ["Completed", "Cancelled"]:
            t["is_overdue"] = str(t["due_date"]) < today_str
        else:
            t["is_overdue"] = False

    return jsonify(json_ready({
        "tasks": tasks,
        "total": total_count,
        "page": page,
        "limit": limit,
        "pages": (total_count + limit - 1) // limit
    }))


@task_bp.route("/api/tasks", methods=["POST"])
def api_tasks_create():
    user = require_current_user()
    db = get_db()
    ensure_task_settings()
    data = request.get_json() or {}

    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Task title is mandatory"}), 400

    task_type = (data.get("task_type") or "").strip()
    if not task_type:
        return jsonify({"error": "Task type is mandatory"}), 400

    priority = (data.get("priority") or "Medium").strip()
    assignee_id = data.get("assignee_id")
    if not assignee_id:
        return jsonify({"error": "Assignee is mandatory"}), 400

    assignee = db.app_users.find_one({"id": int(assignee_id)})
    if not assignee or not assignee.get("is_active", 1):
        return jsonify({"error": "Selected assignee is not an active user"}), 400

    due_date = (data.get("due_date") or "").strip()
    if not due_date:
        return jsonify({"error": "Due date is mandatory"}), 400

    # Sequential ID and Task Number
    task_id = get_next_sequence_value("tasks")
    task_num = get_next_sequence_value("task_number")
    task_number = f"TASK-{str(task_num).zfill(5)}"

    # Resolve linked records
    customer_id = data.get("customer_id")
    customer_name = None
    if customer_id:
        c = db.customers.find_one({"id": int(customer_id)})
        customer_name = c.get("company_name") or c.get("name") if c else None

    project_id = data.get("project_id")
    project_name = None
    if project_id:
        p = db.projects.find_one({"id": int(project_id)})
        project_name = p.get("name") or p.get("title") if p else None

    reviewer_id = data.get("reviewer_id")
    reviewer_name = None
    if reviewer_id:
        r = db.app_users.find_one({"id": int(reviewer_id)})
        reviewer_name = r.get("full_name") if r else None

    # Checklists
    checklists_raw = data.get("checklists") or []
    checklists = []
    for idx, item in enumerate(checklists_raw):
        item_text = (item if isinstance(item, str) else item.get("title") or "").strip()
        if item_text:
            checklists.append({
                "id": idx + 1,
                "title": item_text,
                "is_completed": False,
                "sort_order": idx
            })

    task_doc = {
        "id": task_id,
        "task_number": task_number,
        "title": title,
        "description": (data.get("description") or "").strip(),
        "task_type": task_type,
        "category": (data.get("category") or "General").strip(),
        "priority": priority,
        "status": data.get("status") or "To Do",
        "assignee_id": assignee["id"],
        "assignee_name": assignee.get("full_name"),
        "assignee_email": assignee.get("email"),
        "assignee_notification_email": assignee.get("notification_email") or "",
        "creator_user_id": user["id"],
        "creator_user_name": user.get("full_name"),
        "customer_id": int(customer_id) if customer_id else None,
        "customer_name": customer_name,
        "project_id": int(project_id) if project_id else None,
        "project_name": project_name,
        "environment": (data.get("environment") or "None").strip(),
        "start_date": data.get("start_date") or date.today().strftime("%Y-%m-%d"),
        "due_date": due_date,
        "due_time": (data.get("due_time") or "18:00").strip(),
        "estimated_hours": float(data.get("estimated_hours") or 0.0),
        "actual_hours": float(data.get("actual_hours") or 0.0),
        "tags": [t.strip() for t in (data.get("tags") or []) if t.strip()],
        "review_required": bool(data.get("review_required", False)),
        "reviewer_id": int(reviewer_id) if reviewer_id else None,
        "reviewer_name": reviewer_name,
        "sla_status": "Within SLA",
        "is_escalated": False,
        "escalation_level": 0,
        "checklists": checklists,
        "checklist_total": len(checklists),
        "checklist_completed": 0,
        "progress_pct": 0,
        "blocker_reason": None,
        "on_hold_reason": None,
        "cancellation_reason": None,
        "reopen_reason": None,
        "created_at": datetime.now(),
        "updated_at": datetime.now()
    }

    db.tasks.insert_one(task_doc)

    # Log activity
    db.task_activities.insert_one({
        "id": get_next_sequence_value("task_activities"),
        "task_id": task_id,
        "task_number": task_number,
        "action": "CREATED",
        "details": f"Task created and assigned to {assignee.get('full_name')}",
        "user_id": user["id"],
        "user_name": user.get("full_name"),
        "created_at": datetime.now()
    })

    # Dispatch assignment email notification to assignee's notification_email
    send_task_notification(task_doc, "assignment", assignee, user)

    created = db.tasks.find_one({"id": task_id}, {"_id": 0})
    return jsonify(json_ready({"task": created, "message": f"Task {task_number} created successfully"})), 201


@task_bp.route("/api/tasks/<int:task_id>", methods=["GET"])
def api_tasks_detail(task_id):
    require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    comments = list(db.task_comments.find({"task_id": task_id}, {"_id": 0}).sort("created_at", pymongo.ASCENDING))
    activities = list(db.task_activities.find({"task_id": task_id}, {"_id": 0}).sort("created_at", pymongo.DESCENDING))
    time_logs = list(db.task_time_logs.find({"task_id": task_id}, {"_id": 0}).sort("created_at", pymongo.DESCENDING))
    dependencies = list(db.task_dependencies.find({"task_id": task_id}, {"_id": 0}))
    attachments = list(db.task_attachments.find({"task_id": task_id}, {"_id": 0}))

    # Dynamic overdue check
    today_str = date.today().strftime("%Y-%m-%d")
    if task.get("due_date") and task.get("status") not in ["Completed", "Cancelled"]:
        task["is_overdue"] = str(task["due_date"]) < today_str
    else:
        task["is_overdue"] = False

    return jsonify(json_ready({
        "task": task,
        "comments": comments,
        "activities": activities,
        "time_logs": time_logs,
        "dependencies": dependencies,
        "attachments": attachments
    }))


@task_bp.route("/api/tasks/<int:task_id>", methods=["PUT"])
def api_tasks_update(task_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    updates = {}
    activity_entries = []

    # Title
    if "title" in data and data["title"].strip() and data["title"].strip() != task.get("title"):
        updates["title"] = data["title"].strip()
        activity_entries.append(f"Title changed from '{task.get('title')}' to '{updates['title']}'")

    # Description
    if "description" in data and data["description"] != task.get("description"):
        updates["description"] = data["description"]
        activity_entries.append("Task description updated")

    # Priority
    if "priority" in data and data["priority"] != task.get("priority"):
        updates["priority"] = data["priority"]
        activity_entries.append(f"Priority changed from {task.get('priority')} to {data['priority']}")

    # Task Type
    if "task_type" in data and data["task_type"] != task.get("task_type"):
        updates["task_type"] = data["task_type"]
        activity_entries.append(f"Task type changed to {data['task_type']}")

    # Due date
    if "due_date" in data and data["due_date"] != task.get("due_date"):
        updates["due_date"] = data["due_date"]
        activity_entries.append(f"Due date changed from {task.get('due_date')} to {data['due_date']}")

    # Environment
    if "environment" in data:
        updates["environment"] = data["environment"]

    # Estimated / actual hours
    if "estimated_hours" in data:
        updates["estimated_hours"] = float(data["estimated_hours"] or 0)
    if "actual_hours" in data:
        updates["actual_hours"] = float(data["actual_hours"] or 0)

    # Reassignment
    reassigned_user = None
    if "assignee_id" in data and int(data["assignee_id"]) != task.get("assignee_id"):
        new_assignee = db.app_users.find_one({"id": int(data["assignee_id"])})
        if new_assignee:
            updates["assignee_id"] = new_assignee["id"]
            updates["assignee_name"] = new_assignee.get("full_name")
            updates["assignee_email"] = new_assignee.get("email")
            updates["assignee_notification_email"] = new_assignee.get("notification_email") or ""
            reassigned_user = new_assignee
            activity_entries.append(f"Reassigned from {task.get('assignee_name')} to {new_assignee.get('full_name')}")

    updates["updated_at"] = datetime.now()
    db.tasks.update_one({"id": task_id}, {"$set": updates})

    # Record activity entries
    for act in activity_entries:
        db.task_activities.insert_one({
            "id": get_next_sequence_value("task_activities"),
            "task_id": task_id,
            "task_number": task.get("task_number"),
            "action": "UPDATED",
            "details": act,
            "user_id": user["id"],
            "user_name": user.get("full_name"),
            "created_at": datetime.now()
        })

    # If reassigned, notify the new assignee
    if reassigned_user:
        updated_task = db.tasks.find_one({"id": task_id})
        send_task_notification(updated_task, "reassignment", reassigned_user, user)

    updated = db.tasks.find_one({"id": task_id}, {"_id": 0})
    return jsonify(json_ready({"task": updated, "message": "Task updated successfully"}))


@task_bp.route("/api/tasks/<int:task_id>/status", methods=["POST"])
def api_tasks_status(task_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    new_status = data.get("status")
    old_status = task.get("status")

    if not new_status:
        return jsonify({"error": "New status is required"}), 400

    valid_statuses = [
        "Backlog", "To Do", "In Progress", "Blocked", "On Hold",
        "In Review", "Changes Requested", "Completed", "Cancelled"
    ]
    if new_status not in valid_statuses:
        return jsonify({"error": f"Invalid status: {new_status}"}), 400

    updates = {"status": new_status, "updated_at": datetime.now()}
    details = f"Status changed from '{old_status}' to '{new_status}'"

    # Status-specific validations
    if new_status == "Blocked":
        reason = (data.get("blocker_reason") or "").strip()
        if not reason:
            return jsonify({"error": "A blocker reason is mandatory when marking a task Blocked"}), 400
        updates["blocker_reason"] = reason
        details += f". Blocker: {reason}"

    elif new_status == "On Hold":
        reason = (data.get("on_hold_reason") or "").strip()
        if not reason:
            return jsonify({"error": "An on-hold reason is mandatory when placing a task On Hold"}), 400
        updates["on_hold_reason"] = reason
        details += f". Reason: {reason}"

    elif new_status == "Changes Requested":
        reason = (data.get("changes_requested_reason") or "").strip()
        if not reason:
            return jsonify({"error": "Please provide the changes requested or review feedback"}), 400
        updates["changes_requested_reason"] = reason
        details += f". Changes requested: {reason}"

    elif new_status == "Cancelled":
        reason = (data.get("cancellation_reason") or "").strip()
        if not reason:
            return jsonify({"error": "Cancellation reason is mandatory"}), 400
        updates["cancellation_reason"] = reason
        details += f". Cancellation reason: {reason}"

    elif new_status == "Completed":
        # Check if mandatory subtasks are incomplete
        incomplete_subs = [c for c in task.get("checklists", []) if not c.get("is_completed")]
        if incomplete_subs and data.get("force") is not True:
            return jsonify({
                "error": f"Cannot complete task: {len(incomplete_subs)} subtask(s) remain incomplete.",
                "incomplete_count": len(incomplete_subs)
            }), 400
        updates["completed_at"] = datetime.now()
        updates["progress_pct"] = 100

    elif old_status == "Completed" and new_status != "Completed":
        reason = (data.get("reopen_reason") or "").strip()
        updates["reopen_reason"] = reason
        details += f". Reopened reason: {reason or 'Not specified'}"

    if new_status == "In Progress" and not task.get("started_at"):
        updates["started_at"] = datetime.now()

    db.tasks.update_one({"id": task_id}, {"$set": updates})

    # Log activity
    db.task_activities.insert_one({
        "id": get_next_sequence_value("task_activities"),
        "task_id": task_id,
        "task_number": task.get("task_number"),
        "action": "STATUS_CHANGED",
        "previous_value": old_status,
        "new_value": new_status,
        "details": details,
        "user_id": user["id"],
        "user_name": user.get("full_name"),
        "created_at": datetime.now()
    })

    # Notify assignee if changed by someone else, or notify creator if completed/in review
    updated_task = db.tasks.find_one({"id": task_id})
    if task.get("assignee_id") != user["id"]:
        assignee = db.app_users.find_one({"id": task.get("assignee_id")})
        send_task_notification(updated_task, "status_change", assignee, user)
    elif new_status in ["In Review", "Completed"] and task.get("creator_user_id") != user["id"]:
        creator = db.app_users.find_one({"id": task.get("creator_user_id")})
        send_task_notification(updated_task, "status_change", creator, user)

    return jsonify(json_ready({"task": updated_task, "message": f"Status updated to {new_status}"}))


@task_bp.route("/api/tasks/<int:task_id>/comments", methods=["POST"])
def api_tasks_comment(task_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    comment_text = (data.get("comment_text") or "").strip()
    if not comment_text:
        return jsonify({"error": "Comment cannot be empty"}), 400

    comment_id = get_next_sequence_value("task_comments")
    comment_doc = {
        "id": comment_id,
        "task_id": task_id,
        "task_number": task.get("task_number"),
        "author_id": user["id"],
        "author_name": user.get("full_name"),
        "comment_text": comment_text,
        "created_at": datetime.now()
    }
    db.task_comments.insert_one(comment_doc)

    db.task_activities.insert_one({
        "id": get_next_sequence_value("task_activities"),
        "task_id": task_id,
        "task_number": task.get("task_number"),
        "action": "COMMENT_ADDED",
        "details": f"{user.get('full_name')} commented: {comment_text[:60]}...",
        "user_id": user["id"],
        "user_name": user.get("full_name"),
        "created_at": datetime.now()
    })

    # Notify other party (assignee or creator)
    target_id = task.get("creator_user_id") if user["id"] == task.get("assignee_id") else task.get("assignee_id")
    if target_id and target_id != user["id"]:
        target_user = db.app_users.find_one({"id": target_id})
        send_task_notification(task, "comment", target_user, user, extra={"comment_text": comment_text})

    return jsonify(json_ready({"comment": comment_doc, "message": "Comment posted"})), 201


@task_bp.route("/api/tasks/<int:task_id>/checklists", methods=["POST"])
def api_tasks_add_checklist(task_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Checklist item title is required"}), 400

    items = task.get("checklists") or []
    new_id = len(items) + 1
    new_item = {
        "id": new_id,
        "title": title,
        "is_completed": False,
        "created_at": datetime.now()
    }
    items.append(new_item)

    total = len(items)
    completed = sum(1 for it in items if it.get("is_completed"))
    pct = int(round((completed / total) * 100)) if total > 0 else 0

    db.tasks.update_one({"id": task_id}, {
        "$set": {
            "checklists": items,
            "checklist_total": total,
            "checklist_completed": completed,
            "progress_pct": pct,
            "updated_at": datetime.now()
        }
    })

    return jsonify(json_ready({"item": new_item, "progress_pct": pct})), 201


@task_bp.route("/api/tasks/<int:task_id>/checklists/<int:item_id>", methods=["PUT"])
def api_tasks_toggle_checklist(task_id, item_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    items = task.get("checklists") or []
    found = False

    for it in items:
        if it.get("id") == item_id:
            if "is_completed" in data:
                it["is_completed"] = bool(data["is_completed"])
                it["completed_at"] = datetime.now() if it["is_completed"] else None
                it["completed_by"] = user.get("full_name") if it["is_completed"] else None
            if "title" in data and data["title"].strip():
                it["title"] = data["title"].strip()
            found = True
            break

    if not found:
        return jsonify({"error": "Checklist item not found"}), 404

    total = len(items)
    completed = sum(1 for it in items if it.get("is_completed"))
    pct = int(round((completed / total) * 100)) if total > 0 else 0

    db.tasks.update_one({"id": task_id}, {
        "$set": {
            "checklists": items,
            "checklist_total": total,
            "checklist_completed": completed,
            "progress_pct": pct,
            "updated_at": datetime.now()
        }
    })

    return jsonify(json_ready({"checklists": items, "progress_pct": pct}))


@task_bp.route("/api/tasks/<int:task_id>/time-logs", methods=["POST"])
def api_tasks_add_time_log(task_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    hours = float(data.get("hours") or 0.0)
    if hours <= 0:
        return jsonify({"error": "Duration must be greater than 0 hours"}), 400

    log_id = get_next_sequence_value("task_time_logs")
    log_doc = {
        "id": log_id,
        "task_id": task_id,
        "task_number": task.get("task_number"),
        "user_id": user["id"],
        "user_name": user.get("full_name"),
        "hours": hours,
        "work_date": data.get("work_date") or date.today().strftime("%Y-%m-%d"),
        "description": (data.get("description") or "").strip(),
        "created_at": datetime.now()
    }
    db.task_time_logs.insert_one(log_doc)

    new_actual = round(float(task.get("actual_hours") or 0.0) + hours, 2)
    db.tasks.update_one({"id": task_id}, {"$set": {"actual_hours": new_actual, "updated_at": datetime.now()}})

    db.task_activities.insert_one({
        "id": get_next_sequence_value("task_activities"),
        "task_id": task_id,
        "task_number": task.get("task_number"),
        "action": "TIME_LOGGED",
        "details": f"{user.get('full_name')} logged {hours}h: {data.get('description', '')}",
        "user_id": user["id"],
        "user_name": user.get("full_name"),
        "created_at": datetime.now()
    })

    return jsonify(json_ready({"time_log": log_doc, "actual_hours": new_actual})), 201


@task_bp.route("/api/tasks/<int:task_id>/dependencies", methods=["POST"])
def api_tasks_add_dependency(task_id):
    user = require_current_user()
    db = get_db()
    task = db.tasks.find_one({"id": task_id})
    if not task:
        return jsonify({"error": "Task not found"}), 404

    data = request.get_json() or {}
    depends_on_id = int(data.get("depends_on_task_id") or 0)
    if not depends_on_id or depends_on_id == task_id:
        return jsonify({"error": "Invalid dependent task"}), 400

    depends_task = db.tasks.find_one({"id": depends_on_id})
    if not depends_task:
        return jsonify({"error": "Dependent task does not exist"}), 404

    # Prevent circular dependency (check if depends_task directly or indirectly depends on task_id)
    circular = db.task_dependencies.find_one({"task_id": depends_on_id, "depends_on_task_id": task_id})
    if circular:
        return jsonify({"error": "Circular dependency detected! Cannot make task dependent on a task that depends on it."}), 400

    dep_id = get_next_sequence_value("task_dependencies")
    dep_doc = {
        "id": dep_id,
        "task_id": task_id,
        "depends_on_task_id": depends_on_id,
        "depends_on_task_number": depends_task.get("task_number"),
        "depends_on_task_title": depends_task.get("title"),
        "depends_on_task_status": depends_task.get("status"),
        "created_at": datetime.now()
    }
    db.task_dependencies.insert_one(dep_doc)

    return jsonify(json_ready({"dependency": dep_doc, "message": "Dependency linked"})), 201


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard & Reports Aggregations
# ─────────────────────────────────────────────────────────────────────────────

@task_bp.route("/api/tasks/dashboard-metrics", methods=["GET"])
def api_tasks_dashboard_metrics():
    user = require_current_user()
    db = get_db()
    today_str = date.today().strftime("%Y-%m-%d")
    week_ago = datetime.now() - timedelta(days=7)

    open_filter = {"status": {"$nin": ["Completed", "Cancelled"]}}

    total_open = db.tasks.count_documents(open_filter)
    my_open = db.tasks.count_documents({**open_filter, "assignee_id": user["id"]})
    due_today = db.tasks.count_documents({**open_filter, "due_date": today_str})
    overdue = db.tasks.count_documents({**open_filter, "due_date": {"$lt": today_str}})
    critical = db.tasks.count_documents({**open_filter, "priority": "Critical"})
    blocked = db.tasks.count_documents({"status": "Blocked"})
    awaiting_review = db.tasks.count_documents({"status": "In Review"})
    completed_this_week = db.tasks.count_documents({"status": "Completed", "completed_at": {"$gte": week_ago}})
    sla_breaches = db.tasks.count_documents({"$or": [{"sla_status": "Breached"}, {"is_escalated": True}]})

    # Status breakdown
    status_agg = list(db.tasks.aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]))
    by_status = {s["_id"]: s["count"] for s in status_agg if s["_id"]}

    # Priority breakdown
    priority_agg = list(db.tasks.aggregate([
        {"$match": open_filter},
        {"$group": {"_id": "$priority", "count": {"$sum": 1}}}
    ]))
    by_priority = {p["_id"]: p["count"] for p in priority_agg if p["_id"]}

    # Top assignees
    assignee_agg = list(db.tasks.aggregate([
        {"$match": open_filter},
        {"$group": {"_id": "$assignee_name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 8}
    ]))
    by_assignee = [{"name": a["_id"] or "Unassigned", "count": a["count"]} for a in assignee_agg]

    # Recent activity
    recent_activities = list(db.task_activities.find({}, {"_id": 0}).sort("created_at", pymongo.DESCENDING).limit(8))

    return jsonify(json_ready({
        "metrics": {
            "total_open": total_open,
            "my_open": my_open,
            "due_today": due_today,
            "overdue": overdue,
            "critical": critical,
            "blocked": blocked,
            "awaiting_review": awaiting_review,
            "completed_this_week": completed_this_week,
            "sla_breaches": sla_breaches
        },
        "by_status": by_status,
        "by_priority": by_priority,
        "by_assignee": by_assignee,
        "recent_activities": recent_activities
    }))


@task_bp.route("/api/tasks/reports", methods=["GET"])
def api_tasks_reports():
    require_current_user()
    db = get_db()
    today_str = date.today().strftime("%Y-%m-%d")

    # Team workload
    team_workload = list(db.tasks.aggregate([
        {"$match": {"status": {"$nin": ["Completed", "Cancelled"]}}},
        {"$group": {
            "_id": "$assignee_name",
            "total_tasks": {"$sum": 1},
            "estimated_hours": {"$sum": "$estimated_hours"},
            "actual_hours": {"$sum": "$actual_hours"}
        }},
        {"$sort": {"total_tasks": -1}}
    ]))

    # Overdue task list
    overdue_tasks = list(db.tasks.find({
        "status": {"$nin": ["Completed", "Cancelled"]},
        "due_date": {"$lt": today_str}
    }, {"_id": 0, "id": 1, "task_number": 1, "title": 1, "assignee_name": 1, "priority": 1, "due_date": 1, "status": 1}).sort("due_date", 1).limit(20))

    # Tasks by project
    by_project = list(db.tasks.aggregate([
        {"$match": {"project_name": {"$ne": None}}},
        {"$group": {"_id": "$project_name", "count": {"$sum": 1}, "completed": {"$sum": {"$cond": [{"$eq": ["$status", "Completed"]}, 1, 0]}}}},
        {"$sort": {"count": -1}}
    ]))

    # Tasks by type
    by_type = list(db.tasks.aggregate([
        {"$group": {"_id": "$task_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]))

    return jsonify(json_ready({
        "team_workload": [{"name": w["_id"] or "Unassigned", "tasks": w["total_tasks"], "est_hours": w["estimated_hours"], "act_hours": w["actual_hours"]} for w in team_workload],
        "overdue_tasks": overdue_tasks,
        "by_project": [{"project": p["_id"], "count": p["count"], "completed": p["completed"]} for p in by_project],
        "by_type": [{"type": t["_id"] or "Other", "count": t["count"]} for t in by_type]
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Task Settings & Escalations
# ─────────────────────────────────────────────────────────────────────────────

@task_bp.route("/api/tasks/settings", methods=["GET"])
def api_tasks_get_settings():
    require_current_user()
    settings = ensure_task_settings()
    # Mask password for security
    sanitized = dict(settings)
    if "smtp_settings" in sanitized and sanitized["smtp_settings"].get("password"):
        sanitized["smtp_settings"] = dict(sanitized["smtp_settings"])
        sanitized["smtp_settings"]["password"] = "********"
    return jsonify(json_ready({"settings": sanitized}))


@task_bp.route("/api/tasks/settings", methods=["PUT"])
def api_tasks_update_settings():
    require_current_user()
    db = get_db()
    data = request.get_json() or {}

    current = ensure_task_settings()
    updates = {"updated_at": datetime.now()}

    if "task_types" in data:
        updates["task_types"] = data["task_types"]
    if "categories" in data:
        updates["categories"] = data["categories"]
    if "sla_policies" in data:
        updates["sla_policies"] = data["sla_policies"]
    if "escalation_rules" in data:
        updates["escalation_rules"] = data["escalation_rules"]
    if "notification_preferences" in data:
        updates["notification_preferences"] = data["notification_preferences"]

    if "smtp_settings" in data:
        new_smtp = dict(data["smtp_settings"])
        # Retain existing password if masked
        if new_smtp.get("password") == "********":
            new_smtp["password"] = current.get("smtp_settings", {}).get("password", "")
        updates["smtp_settings"] = new_smtp

    db.task_settings.update_one({"id": "default"}, {"$set": updates})
    updated = db.task_settings.find_one({"id": "default"})
    return jsonify(json_ready({"settings": updated, "message": "Task settings updated successfully"}))


@task_bp.route("/api/tasks/run-escalations", methods=["POST"])
def api_tasks_run_escalations():
    require_current_user()
    db = get_db()
    today_str = date.today().strftime("%Y-%m-%d")

    # Find overdue open tasks
    overdue_tasks = list(db.tasks.find({
        "status": {"$nin": ["Completed", "Cancelled"]},
        "due_date": {"$lt": today_str}
    }))

    escalated_count = 0
    now = datetime.now()

    for t in overdue_tasks:
        due_dt = datetime.strptime(t["due_date"], "%Y-%m-%d")
        hours_overdue = (now - due_dt).total_seconds() / 3600.0

        target_level = 0
        if hours_overdue >= 48:
            target_level = 2
        elif hours_overdue >= 24:
            target_level = 1

        if target_level > 0 and t.get("escalation_level", 0) < target_level:
            db.tasks.update_one({"id": t["id"]}, {
                "$set": {
                    "is_escalated": True,
                    "escalation_level": target_level,
                    "sla_status": "Breached",
                    "updated_at": now
                }
            })

            # Record escalation
            db.task_escalations.insert_one({
                "id": get_next_sequence_value("task_escalations"),
                "task_id": t["id"],
                "task_number": t.get("task_number"),
                "level": target_level,
                "hours_overdue": round(hours_overdue, 1),
                "triggered_at": now
            })

            # Send escalation email to assignee
            if t.get("assignee_id"):
                assignee = db.app_users.find_one({"id": t["assignee_id"]})
                send_task_notification(t, "escalation", assignee, None)

            escalated_count += 1

    return jsonify(json_ready({"escalated_count": escalated_count, "message": f"{escalated_count} task(s) processed for escalation"}))


def init_task_module(app):
    app.register_blueprint(task_bp)
    print("✓ Task Management Module initialized and routes registered.")
