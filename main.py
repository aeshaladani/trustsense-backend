from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import random
import asyncio
import json
import time
import math
from datetime import datetime, timedelta
from typing import Optional
import uuid
import os
import httpx
from contextlib import asynccontextmanager

# ── Keep-alive background task ────────────────────────────────────────────────
# Pings itself every 10 minutes so Render free tier never sleeps
async def keep_alive():
    await asyncio.sleep(30)  # wait for server to fully start first
    while True:
        try:
            own_url = os.environ.get("RENDER_EXTERNAL_URL", "http://localhost:8000")
            async with httpx.AsyncClient() as client:
                await client.get(f"{own_url}/health", timeout=10)
            print(f"[keep-alive] pinged at {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            print(f"[keep-alive] ping failed: {e}")
        await asyncio.sleep(600)  # ping every 10 minutes

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start keep-alive task on boot
    task = asyncio.create_task(keep_alive())
    yield
    task.cancel()

app = FastAPI(title="TrustSense AI — Demo Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory state for demo ─────────────────────────────────────────────────
sessions: dict = {}
flagged_sessions: list = []
kyc_submissions: list = []

RISK_EVENTS = [
    {"type": "new_device",       "label": "New device detected",          "impact": -22, "icon": "device"},
    {"type": "geo_anomaly",      "label": "Login from new location",       "impact": -18, "icon": "map"},
    {"type": "velocity",         "label": "High transaction velocity",     "impact": -15, "icon": "bolt"},
    {"type": "odd_hours",        "label": "Access outside normal hours",   "impact": -12, "icon": "clock"},
    {"type": "vpn_detected",     "label": "VPN / proxy detected",          "impact": -10, "icon": "shield"},
    {"type": "failed_attempts",  "label": "Multiple failed attempts",      "impact": -25, "icon": "lock"},
    {"type": "sim_swap",         "label": "SIM swap signal detected",      "impact": -30, "icon": "phone"},
    {"type": "large_transfer",   "label": "Unusually large transfer",      "impact": -14, "icon": "transfer"},
    {"type": "privileged_bulk",  "label": "Bulk record access by employee","impact": -28, "icon": "eye"},
    {"type": "typing_anomaly",   "label": "Typing pattern mismatch",       "impact": -8,  "icon": "keyboard"},
]

SAMPLE_USERS = [
    {"id": "u001", "name": "Priya Sharma",    "account": "SB-4821-7734", "role": "Customer"},
    {"id": "u002", "name": "Rajan Mehta",     "account": "SB-2293-1156", "role": "Customer"},
    {"id": "u003", "name": "Anita Desai",     "account": "CB-9910-3342", "role": "Customer"},
    {"id": "u004", "name": "Vivek Joshi",     "account": "SB-6672-8891", "role": "Employee (RM)"},
    {"id": "u005", "name": "Sneha Kulkarni",  "account": "SB-3384-5529", "role": "Customer"},
]

# ── Models ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    user_id: str
    device_id: str
    ip_address: str
    latitude: Optional[float] = 19.076
    longitude: Optional[float] = 72.877
    user_agent: str = "Mozilla/5.0"

class TransactionRequest(BaseModel):
    session_id: str
    amount: float
    recipient: str
    transaction_type: str = "transfer"

class KYCSubmission(BaseModel):
    full_name: str
    dob: str
    document_type: str
    document_number: str
    selfie_score: float = 0.0
    liveness_score: float = 0.0

class MFAVerify(BaseModel):
    session_id: str
    otp: str

# ── Helpers ──────────────────────────────────────────────────────────────────
def compute_trust_score(session: dict) -> float:
    base = session.get("base_score", 85.0)
    penalties = sum(e["impact"] for e in session.get("events", []))
    score = max(0, min(100, base + penalties))
    return round(score, 1)

def get_risk_level(score: float) -> dict:
    if score >= 85:
        return {"level": "low",      "label": "Trusted",    "action": "allow",   "color": "green"}
    elif score >= 60:
        return {"level": "guarded",  "label": "Guarded",    "action": "monitor", "color": "blue"}
    elif score >= 40:
        return {"level": "elevated", "label": "Elevated",   "action": "stepup",  "color": "amber"}
    elif score >= 20:
        return {"level": "high",     "label": "High Risk",  "action": "freeze",  "color": "coral"}
    else:
        return {"level": "critical", "label": "Critical",   "action": "block",   "color": "red"}

def make_session(user_id: str, device_id: str, ip: str) -> dict:
    user = next((u for u in SAMPLE_USERS if u["id"] == user_id), SAMPLE_USERS[0])
    known_device = device_id.startswith("known-")
    known_ip = ip.startswith("192.168") or ip == "10.0.0.1"
    base = 88 if (known_device and known_ip) else (72 if known_device else 58)
    session_id = str(uuid.uuid4())[:8]
    events = []
    if not known_device:
        events.append({**RISK_EVENTS[0], "timestamp": datetime.now().isoformat()})
    if not known_ip:
        events.append({**RISK_EVENTS[1], "timestamp": datetime.now().isoformat()})
    now = datetime.now().hour
    if now < 6 or now > 22:
        events.append({**RISK_EVENTS[3], "timestamp": datetime.now().isoformat()})
    session = {
        "session_id": session_id,
        "user": user,
        "device_id": device_id,
        "ip_address": ip,
        "base_score": float(base),
        "events": events,
        "created_at": datetime.now().isoformat(),
        "status": "active",
        "mfa_required": False,
        "mfa_verified": False,
        "score_history": [],
    }
    score = compute_trust_score(session)
    session["score_history"].append({"t": 0, "score": score})
    sessions[session_id] = session
    return session

# ── Routes ───────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"service": "TrustSense AI", "status": "running", "version": "1.0-demo"}

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}

@app.get("/api/users")
def get_users():
    return SAMPLE_USERS

@app.post("/api/session/login")
def login(req: LoginRequest):
    session = make_session(req.user_id, req.device_id, req.ip_address)
    score = compute_trust_score(session)
    risk = get_risk_level(score)
    if risk["action"] in ("stepup", "freeze", "block"):
        session["mfa_required"] = True
    return {
        "session_id": session["session_id"],
        "user": session["user"],
        "trust_score": score,
        "risk": risk,
        "events": session["events"],
        "mfa_required": session["mfa_required"],
    }

@app.get("/api/session/{session_id}")
def get_session(session_id: str):
    s = sessions.get(session_id)
    if not s:
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    score = compute_trust_score(s)
    risk = get_risk_level(score)
    return {
        "session_id": session_id,
        "user": s["user"],
        "trust_score": score,
        "risk": risk,
        "events": s["events"],
        "score_history": s["score_history"],
        "mfa_required": s["mfa_required"],
        "mfa_verified": s["mfa_verified"],
        "status": s["status"],
    }

@app.post("/api/session/{session_id}/event")
def inject_event(session_id: str, event_type: str):
    s = sessions.get(session_id)
    if not s:
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    event = next((e for e in RISK_EVENTS if e["type"] == event_type), None)
    if not event:
        return JSONResponse(status_code=400, content={"error": "Unknown event type"})
    e = {**event, "timestamp": datetime.now().isoformat()}
    s["events"].append(e)
    score = compute_trust_score(s)
    t = len(s["score_history"])
    s["score_history"].append({"t": t, "score": score})
    risk = get_risk_level(score)
    if risk["action"] in ("stepup", "freeze", "block") and not s["mfa_verified"]:
        s["mfa_required"] = True
    if s["session_id"] not in [f["session_id"] for f in flagged_sessions] and risk["level"] in ("high", "critical", "elevated"):
        flagged_sessions.append({
            "session_id": s["session_id"],
            "user": s["user"],
            "trust_score": score,
            "risk": risk,
            "top_event": event["label"],
            "flagged_at": datetime.now().isoformat(),
        })
    return {
        "trust_score": score,
        "risk": risk,
        "event_added": e,
        "mfa_required": s["mfa_required"],
    }

@app.post("/api/session/{session_id}/mfa")
def verify_mfa(session_id: str, body: MFAVerify):
    s = sessions.get(session_id)
    if not s:
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    success = body.otp == "123456"
    if success:
        s["mfa_verified"] = True
        s["mfa_required"] = False
        s["base_score"] = min(100, s["base_score"] + 15)
        s["events"] = [e for e in s["events"] if e["type"] not in ("new_device", "geo_anomaly")]
    score = compute_trust_score(s)
    t = len(s["score_history"])
    s["score_history"].append({"t": t, "score": score})
    return {"success": success, "trust_score": score, "risk": get_risk_level(score)}

@app.post("/api/transaction")
def create_transaction(req: TransactionRequest):
    s = sessions.get(req.session_id)
    if not s:
        return JSONResponse(status_code=404, content={"error": "Session not found"})
    score = compute_trust_score(s)
    if req.amount > 50000:
        e = {**RISK_EVENTS[7], "timestamp": datetime.now().isoformat()}
        s["events"].append(e)
        score = compute_trust_score(s)
        t = len(s["score_history"])
        s["score_history"].append({"t": t, "score": score})
    risk = get_risk_level(score)
    allowed = risk["action"] not in ("block", "freeze")
    return {
        "allowed": allowed,
        "trust_score": score,
        "risk": risk,
        "mfa_required": risk["action"] == "stepup",
        "message": "Transaction approved" if allowed else "Transaction blocked — high risk detected",
    }

@app.post("/api/kyc/submit")
def submit_kyc(req: KYCSubmission):
    doc_score = random.uniform(0.6, 1.0)
    liveness = req.liveness_score if req.liveness_score > 0 else random.uniform(0.55, 0.98)
    selfie = req.selfie_score if req.selfie_score > 0 else random.uniform(0.60, 0.99)
    flags = []
    if doc_score < 0.75:
        flags.append({"flag": "document_quality", "label": "Low document quality score", "severity": "medium"})
    if liveness < 0.70:
        flags.append({"flag": "liveness_fail",    "label": "Liveness check uncertain",   "severity": "high"})
    if selfie < 0.72:
        flags.append({"flag": "face_mismatch",    "label": "Face match below threshold", "severity": "high"})
    if req.document_number.startswith("000"):
        flags.append({"flag": "doc_pattern",      "label": "Document pattern anomaly",   "severity": "high"})
    overall = (doc_score * 0.3 + liveness * 0.4 + selfie * 0.3) * 100
    verdict = "approved" if overall >= 72 and len([f for f in flags if f["severity"] == "high"]) == 0 else ("review" if overall >= 55 else "rejected")
    submission = {
        "id": str(uuid.uuid4())[:8],
        "name": req.full_name,
        "document_type": req.document_type,
        "doc_score": round(doc_score * 100, 1),
        "liveness_score": round(liveness * 100, 1),
        "selfie_score": round(selfie * 100, 1),
        "overall_score": round(overall, 1),
        "flags": flags,
        "verdict": verdict,
        "submitted_at": datetime.now().isoformat(),
    }
    kyc_submissions.append(submission)
    return submission

@app.get("/api/analyst/dashboard")
def analyst_dashboard():
    all_sessions = []
    for sid, s in sessions.items():
        score = compute_trust_score(s)
        risk = get_risk_level(score)
        all_sessions.append({
            "session_id": sid,
            "user": s["user"],
            "trust_score": score,
            "risk": risk,
            "event_count": len(s["events"]),
            "created_at": s["created_at"],
            "mfa_verified": s["mfa_verified"],
        })
    stats = {
        "total_sessions": len(sessions),
        "flagged": len([s for s in all_sessions if s["risk"]["level"] in ("high","critical")]),
        "mfa_triggered": len([s for s in all_sessions if s["mfa_verified"]]),
        "kyc_submissions": len(kyc_submissions),
        "kyc_approved": len([k for k in kyc_submissions if k["verdict"] == "approved"]),
        "kyc_review": len([k for k in kyc_submissions if k["verdict"] == "review"]),
        "kyc_rejected": len([k for k in kyc_submissions if k["verdict"] == "rejected"]),
    }
    return {
        "stats": stats,
        "sessions": sorted(all_sessions, key=lambda x: x["trust_score"]),
        "flagged_sessions": flagged_sessions[-10:],
        "kyc_submissions": kyc_submissions[-10:],
    }

@app.get("/api/risk-events")
def get_risk_events():
    return RISK_EVENTS

@app.websocket("/ws/session/{session_id}")
async def session_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()
    try:
        tick = 0
        while True:
            s = sessions.get(session_id)
            if not s:
                await websocket.send_json({"error": "Session not found"})
                break
            score = compute_trust_score(s)
            jitter = random.uniform(-1.5, 1.5)
            score = max(0, min(100, score + jitter))
            t = len(s["score_history"])
            s["score_history"].append({"t": t, "score": round(score, 1)})
            risk = get_risk_level(score)
            await websocket.send_json({
                "trust_score": round(score, 1),
                "risk": risk,
                "tick": tick,
                "events": s["events"][-3:],
            })
            tick += 1
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
