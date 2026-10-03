"""
Orchestration launcher for the End-to-End Proctoring Testbed Suite.
Starts the FastAPI backend, serves the Web UI, and initializes demo sessions.
"""

import os
import sys
import time
import webbrowser
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
WEB_UI_DIR = ROOT_DIR / "web-ui"
COMPANION_DIR = ROOT_DIR / "companion-agent"

# Add backend to path
sys.path.insert(0, str(BACKEND_DIR))

def setup_demo_data():
    from src.database.db import Database
    db_path = str(BACKEND_DIR / "proctor.db")
    db = Database(db_path=db_path)
    
    session_id = "DEMO-SESSION-001"
    existing = db.get_session(session_id)
    if not existing:
        print(f"[*] Initializing default session: {session_id}...")
        db.create_session(
            session_id=session_id,
            name="Computer Science 401 - System Architecture Final",
            config={
                "durationMinutes": 60,
                "allowCalculator": False,
                "strictFullscreen": True,
                "companionAgentRequired": False
            }
        )
        # Seed demo candidate
        db.upsert_candidate(session_id, "CAND-89421", name="Alex Rivera", status="ACTIVE")
        db.upsert_candidate(session_id, "CAND-10293", name="Jordan Chen", status="ACTIVE")
        db.upsert_candidate(session_id, "CAND-55102", name="Samantha Vance", status="ACTIVE")
        print("[+] Demo session & candidates initialized.")

def main():
    print("=" * 68)
    print("      PROCTORGUARD - COMPREHENSIVE PROCTORING TESTBED SUITE")
    print("=" * 68)
    print(f"Root Directory: {ROOT_DIR}")
    print(f"Web UI:         {WEB_UI_DIR}")
    print(f"Companion App:  {COMPANION_DIR}")
    print("-" * 68)

    setup_demo_data()

    port = int(os.environ.get("PROCTOR_PORT", 8080))
    print(f"\n[>] Starting FastAPI Backend Server on http://127.0.0.1:{port} ...")
    print(f"    - Candidate Portal:  http://127.0.0.1:{port}/app/candidate/index.html")
    print(f"    - Admin Dashboard:   http://127.0.0.1:{port}/app/admin/dashboard.html")
    print(f"    - Incident Review:   http://127.0.0.1:{port}/app/admin/review.html")
    print(f"    - Cheat Simulator:   http://127.0.0.1:{port}/app/admin/simulator.html")
    print(f"    - Suite Home:        http://127.0.0.1:{port}/app/index.html\n")

    import uvicorn
    from src.server import app

    # Launch browser automatically
    def open_portal():
        time.sleep(1.2)
        try:
            webbrowser.open(f"http://127.0.0.1:{port}/app/index.html")
        except Exception:
            pass

    import threading
    threading.Thread(target=open_portal, daemon=True).start()

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")

if __name__ == "__main__":
    main()
