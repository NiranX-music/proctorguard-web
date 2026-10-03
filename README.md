# ProctorGuard Web — Full-Stack Proctoring Suite & AI Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-2.5%20Flash-8E24AA.svg)](https://ai.google.dev/)

**ProctorGuard Web** is a modular, high-integrity automated online proctoring testbed designed to evaluate browser sandbox constraints, real-time threat detection, and multimodal AI audio auditing.

---

## 🏛️ Architecture & System Topology

```
+-----------------------------------------------------------------------------------+
|                            Candidate Browser Workstation                          |
|                                                                                   |
|  +---------------------------+   +------------------------+   +----------------+  |
|  | Compulsory Fullscreen     |   | Extension Blocker      |   | Web Audio VU   |  |
|  | Enforced lock + Auto-pause|   | MutationObserver DOM   |   | AnalyserNode   |  |
|  +-------------+-------------+   +-----------+------------+   +--------+-------+  |
|                |                             |                         |          |
|                +--------------------+--------+-------------------------+          |
|                                     | WebRTC Video & WebSocket Telemetry          |
|                                     v                                             |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                        ProctorGuard FastAPI Backend Service                       |
|                                                                                   |
|  - WebSocket Session Hub & WebRTC Mesh Signaling                                  |
|  - Real-time Incident Scoring Engine: Risk Score = min(100, Σ w_i * N_i)          |
|  - Multimodal Gemini 2.5 Flash Live Audio Auditor                                 |
|  - SQLite WAL Database (Sessions, Candidates, Timestamped Incidents)              |
+-------------------------------------+---------------------------------------------+
                                      | WebSockets & SSE Events
                                      v
+-----------------------------------------------------------------------------------+
|                         Admin & Proctor Live Control Room                         |
|                                                                                   |
|  - Real-Time Candidate Video Matrix & Dynamic Audio VU Volume Meters              |
|  - Live Incident Alert Stream with Severity Pills (Critical, High, Medium, Low)   |
|  - One-Click Remote Controls: Send Warning, Remote Lockdown, Force Terminate      |
|  - Candidate Session Scrubber, Timeline Viewer & JSON Audit Exporter              |
+-----------------------------------------------------------------------------------+
```

---

## 🚀 Key Features

### 1. Compulsory Fullscreen Lockdown & Anti-Cheat
- **Mandatory Fullscreen Gate**: Students cannot interact with the test without entering continuous fullscreen mode.
- **Exit Detection Curtain**: Leaving fullscreen immediately pauses the countdown timer, blurs the test interface with a red violation overlay, increments security strikes, and requires an explicit re-entry action.
- **Whole-Screen Display Enforcement**: Rejects single application window or browser tab sharing using `track.getSettings().displaySurface !== 'monitor'`.
- **Keyboard & System Traps**: Intercepts `Alt+Tab`, `Escape`, `F11`, `F12`, `Ctrl+Shift+I/J/C` (DevTools), `Ctrl+U` (Source), `Ctrl+C/V/X` (Clipboard), and blocks the right-click context menu.

### 2. Browser Extension Detection & Blocker
- Continuous scanning for injected third-party extensions, AI helpers, grammar tools, and script injectors (`Grammarly`, `ChatGPT`, `Copilot`, `Loom`).
- `MutationObserver` actively monitors DOM modifications and immediately halts the exam upon dynamic injection.

### 3. Google Gemini 2.5 Flash Live Audio Auditor
- **Acoustic Anomaly Capture**: Web Audio API monitors ambient volume; upon background talking, whispers, or acoustic bursts, captures a 4-second audio clip.
- **Explanation Modal**: Candidate is prompted to listen to the captured audio and submit an honest explanation.
- **Multimodal AI Analysis**: Backend sends the audio recording and explanation to Gemini 2.5 Flash.
  - **Accepted**: If audio matches benign patterns (e.g. coughing, chair creak, door slam), the warning strike is waived automatically.
  - **Rejected**: If secondary voice or answer reading is detected, the strike is upheld and escalated.

### 4. Real-Time Admin Control Room & Incident Scrubber
- Live multi-candidate streaming grid with real-time volume VU meters.
- Filterable incident alert feed with synchronized snapshot frame inspection.
- Chronological timeline scrubber with violation heatmaps and one-click JSON audit log export.
- Integrated **Cheat Simulation Playground** to test all 12+ violation vectors with one click.

---

## 🛠️ Quickstart

### Prerequisites
- Python 3.10 or higher
- Modern Chromium-based browser (Chrome, Edge, Brave)

### Installation
```bash
# Clone the repository
git clone https://github.com/NiranX-music/proctorguard-web.git
cd proctorguard-web

# Install dependencies
pip install -r backend/requirements.txt
```

### Launch
```bash
# Run the unified launcher (starts server on port 8080)
python run_proctor_suite.py

# Or on Windows:
start_suite.bat
```

Open your browser to **`http://127.0.0.1:8080/app/index.html`** to access the unified portal.

---

## 📡 REST API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | `GET` | Health check and database path verification |
| `/api/config/gemini` | `GET/POST` | Get or update global Google Gemini API Key |
| `/api/ai/verify-audio-explanation` | `POST` | Multimodal Gemini 3.8 Flash audio & explanation evaluation |
| `/api/sessions` | `GET/POST` | List sessions or create a new session |
| `/api/sessions/{session_id}` | `GET` | Session detail, registered candidates, and recent incidents |
| `/api/sessions/{session_id}/incidents` | `GET/POST` | List incidents or post simulated violations |
| `/api/sessions/{session_id}/candidates/{cand_id}/warn` | `POST` | Issue a remote warning strike to candidate |
| `/api/sessions/{session_id}/candidates/{cand_id}/lock` | `POST` | Remote lockdown candidate exam interface |
| `/api/sessions/{session_id}/candidates/{cand_id}/unlock`| `POST` | Remote unlock candidate exam interface |
| `/api/sessions/{session_id}/candidates/{cand_id}/terminate` | `POST` | Force-terminate candidate session |
| `/api/sessions/{session_id}/export` | `GET` | Export complete session audit log in JSON format |

---

## 🧪 Testing

```bash
python backend/tests/run_tests.py
```

---

## 📄 License
Released under the [MIT License](LICENSE).
