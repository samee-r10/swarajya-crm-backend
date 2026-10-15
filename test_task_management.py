import json
from datetime import datetime, date
from app import app, get_db

def run_tests():
    print("==================================================================")
    print("TASK MANAGEMENT & NOTIFICATION INTEGRATION TESTS")
    print("==================================================================")

    db = get_db()
    with app.test_client() as client:
        # Authenticate as active admin user
        admin_user = db.app_users.find_one({"is_active": 1})
        with client.session_transaction() as sess:
            sess["user_id"] = admin_user["id"]

        # Ensure target test assignee exists with a distinct notification_email
        test_assignee = db.app_users.find_one({"email": "aman.yadav@swarajyaconsultancy.in"})
        if not test_assignee:
            test_assignee = db.app_users.find_one({"is_active": 1, "id": {"$ne": admin_user["id"]}})
        
        # Set a distinct notification_email for the assignee
        personal_notif_email = "aman.personal.alerts@testdomain.com"
        db.app_users.update_one(
            {"id": test_assignee["id"]},
            {"$set": {"notification_email": personal_notif_email}}
        )
        test_assignee = db.app_users.find_one({"id": test_assignee["id"]})
        print(f"Assignee: {test_assignee['full_name']} | Company Email: {test_assignee['email']} | Notification Email: {test_assignee['notification_email']}")
        assert test_assignee["notification_email"] == personal_notif_email

        # -------------------------------------------------------------
        # TEST 1: Task Creation with Sequential ID and Auto-Notification
        # -------------------------------------------------------------
        print("\n--- TEST 1: Task Creation with Sequential TASK-xxxxx ID ---")
        task_payload = {
            "title": "Configure Production SSL and Nginx Reverse Proxy",
            "task_type": "Deployment",
            "priority": "High",
            "assignee_id": test_assignee["id"],
            "category": "Infrastructure & Cloud",
            "due_date": date.today().strftime("%Y-%m-%d"),
            "due_time": "18:00",
            "estimated_hours": 3.5,
            "environment": "Production",
            "description": "Install certbot, configure auto-renewal, and verify TLS 1.3 endpoints.",
            "checklists": [
                "Install Certbot on Ubuntu Server",
                "Configure Nginx virtual hosts",
                "Verify HTTPS SSL Labs A+ rating"
            ]
        }
        res_create = client.post("/api/tasks", data=json.dumps(task_payload), content_type="application/json")
        assert res_create.status_code == 201, f"Create failed: {res_create.data}"
        create_data = json.loads(res_create.data)["task"]
        task_id = create_data["id"]
        task_number = create_data["task_number"]
        print(f"✓ Task Created: ID={task_id}, Number={task_number}, Status={create_data['status']}")
        assert task_number.startswith("TASK-"), f"Invalid task number format: {task_number}"

        # -------------------------------------------------------------
        # TEST 2: Verify Email Hit Notification Email (NOT Company Email)
        # -------------------------------------------------------------
        print("\n--- TEST 2: Verify Notification Hit Assignee's Notification Email ---")
        notif = db.task_notifications.find_one({"task_id": task_id, "event_type": "assignment"})
        assert notif is not None, "Assignment notification record was not generated in task_notifications!"
        print(f"✓ Notification Dispatched: Recipient={notif['recipient_email']}, Status={notif['status']}")
        assert notif["recipient_email"] == personal_notif_email, (
            f"Notification went to {notif['recipient_email']} instead of personal notification email {personal_notif_email}!"
        )
        assert notif["recipient_email"] != test_assignee["email"], "Notification was sent to company swarajya email!"
        print("✓ Verified: Alert hit the notification email, NOT the swarajya company email ID!")

        # -------------------------------------------------------------
        # TEST 3: Status Transition Workflow with Reason Validations
        # -------------------------------------------------------------
        print("\n--- TEST 3: Status Transitions with Enforced Reasons ---")
        # 3a: Move to In Progress
        res_prog = client.post(f"/api/tasks/{task_id}/status", data=json.dumps({"status": "In Progress"}), content_type="application/json")
        assert res_prog.status_code == 200
        print("✓ Moved to In Progress")

        # 3b: Blocked without reason must fail
        res_blk_fail = client.post(f"/api/tasks/{task_id}/status", data=json.dumps({"status": "Blocked"}), content_type="application/json")
        assert res_blk_fail.status_code == 400
        print("✓ Blocked without reason properly rejected (400)")

        # 3c: Blocked with reason succeeds
        res_blk_ok = client.post(f"/api/tasks/{task_id}/status", data=json.dumps({
            "status": "Blocked",
            "blocker_reason": "Waiting for Cloudflare DNS delegation token from client"
        }), content_type="application/json")
        assert res_blk_ok.status_code == 200
        print("✓ Blocked with reason succeeded")

        # 3d: Resume to In Progress
        client.post(f"/api/tasks/{task_id}/status", data=json.dumps({"status": "In Progress"}), content_type="application/json")

        # -------------------------------------------------------------
        # TEST 4: Checklist Execution & Completion
        # -------------------------------------------------------------
        print("\n--- TEST 4: Checklist Execution ---")
        detail_res = client.get(f"/api/tasks/{task_id}")
        task_detail = json.loads(detail_res.data)["task"]
        checklists = task_detail["checklists"]
        assert len(checklists) == 3, f"Expected 3 checklist items, found {len(checklists)}"

        for item in checklists:
            res_toggle = client.put(f"/api/tasks/{task_id}/checklists/{item['id']}", data=json.dumps({"is_completed": True}), content_type="application/json")
            assert res_toggle.status_code == 200
        print("✓ All 3 subtasks checked complete")

        # Complete task
        res_comp = client.post(f"/api/tasks/{task_id}/status", data=json.dumps({"status": "Completed"}), content_type="application/json")
        assert res_comp.status_code == 200
        assert json.loads(res_comp.data)["task"]["status"] == "Completed"
        print("✓ Task marked Completed")

        # -------------------------------------------------------------
        # TEST 5: Comments, Time Logs, and Activity Audit Trail
        # -------------------------------------------------------------
        print("\n--- TEST 5: Comments, Time Logging & Activity History ---")
        # Add comment
        res_comm = client.post(f"/api/tasks/{task_id}/comments", data=json.dumps({
            "comment_text": "SSL certificates issued successfully and test suite passed."
        }), content_type="application/json")
        assert res_comm.status_code == 201
        print("✓ Comment posted successfully")

        # Log time
        res_time = client.post(f"/api/tasks/{task_id}/time-logs", data=json.dumps({
            "hours": 2.5,
            "description": "Configured Nginx SSL vhost and verified OCSP stapling"
        }), content_type="application/json")
        assert res_time.status_code == 201
        print("✓ Time logged: 2.5 hours")

        # Check full detail
        full_detail = json.loads(client.get(f"/api/tasks/{task_id}").data)
        assert len(full_detail["comments"]) >= 1
        assert len(full_detail["time_logs"]) >= 1
        assert len(full_detail["activities"]) >= 4
        print(f"✓ Audited Activities: {len(full_detail['activities'])} immutable entries recorded")

        # -------------------------------------------------------------
        # TEST 6: Dashboard Metrics Aggregation
        # -------------------------------------------------------------
        print("\n--- TEST 6: Dashboard Metrics Aggregations ---")
        dash_res = client.get("/api/tasks/dashboard-metrics")
        assert dash_res.status_code == 200
        d_metrics = json.loads(dash_res.data)["metrics"]
        print(f"✓ Dashboard Aggregations: Total Open={d_metrics['total_open']}, My Open={d_metrics['my_open']}, Completed This Week={d_metrics['completed_this_week']}")

        # -------------------------------------------------------------
        # TEST 7: Settings & Master Data Verification
        # -------------------------------------------------------------
        print("\n--- TEST 7: Task Settings & Master Data ---")
        settings_res = client.get("/api/tasks/settings")
        assert settings_res.status_code == 200
        sett = json.loads(settings_res.data)["settings"]
        assert len(sett["task_types"]) >= 10
        assert len(sett["sla_policies"]) == 4
        assert len(sett["escalation_rules"]) == 2
        print("✓ Task Settings, SLA Policies and Escalation Rules validated")

        print("\n==================================================================")
        print("ALL TASK MANAGEMENT & NOTIFICATION TESTS PASSED SUCCESSFULLY!")
        print("==================================================================")

if __name__ == "__main__":
    run_tests()
