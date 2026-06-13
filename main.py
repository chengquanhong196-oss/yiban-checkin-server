"""
yiban-checkin Cloud Service — FastAPI Backend

Endpoints:
  POST /api/register          — Create account (with phone)
  POST /api/login             — Login → JWT
  GET  /api/me                — User profile + subscription
  PUT  /api/me/config         — Update yiban credentials
  GET  /api/me/history        — Check-in history
  POST /api/me/checkin        — Trigger immediate check-in
  POST /api/me/payment-link   — Generate 爱发电 payment link
  GET  /api/health            — Basic health check
  GET  /api/health/detailed   — Detailed stats (admin)
  POST /api/webhook/afdian    — 爱发电 payment webhook
  POST /api/admin/notify      — Broadcast notification to paid users
"""

import hashlib
import logging
import os
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from jose import jwt
from apscheduler.schedulers.background import BackgroundScheduler

from config import CHECKIN_HOUR, CHECKIN_MINUTE, AFDIAN_TOKEN
from models import init_db, get_db, User, CheckinLog
from auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, encrypt_config, decrypt_config, subscription_active,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("server")

# ============================================================
# Startup / Scheduler
# ============================================================

scheduler = BackgroundScheduler()


def scheduled_checkin():
    from checkin_worker import run_daily_checkin
    run_daily_checkin()


def scheduled_monitor():
    from monitor import check_and_alert
    check_and_alert()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 安全检查
    from config import JWT_SECRET, CREDENTIAL_ENCRYPTION_KEY
    if not JWT_SECRET:
        logger.error("❌ JWT_SECRET 未设置！服务器拒绝启动。请在环境变量中设置 JWT_SECRET")
        raise RuntimeError("JWT_SECRET is required")
    if not CREDENTIAL_ENCRYPTION_KEY:
        logger.error("❌ CREDENTIAL_ENCRYPTION_KEY 未设置！服务器拒绝启动。请设置 CREDENTIAL_ENCRYPTION_KEY")
        raise RuntimeError("CREDENTIAL_ENCRYPTION_KEY is required")

    init_db()
    scheduler.add_job(scheduled_checkin, "cron", hour=CHECKIN_HOUR, minute=CHECKIN_MINUTE,
                      timezone="Asia/Shanghai")
    scheduler.add_job(scheduled_monitor, "cron", hour=22, minute=30, timezone="Asia/Shanghai")
    scheduler.start()
    logger.info(f"每日签到: {CHECKIN_HOUR}:{CHECKIN_MINUTE:02d} CST | 每日告警: 22:30 CST")
    yield
    scheduler.shutdown()


app = FastAPI(title="yiban-checkin Cloud", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Web frontend ===
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# WEB_COOKIE_NAME for browser sessions (separate from API Bearer)
WEB_COOKIE_NAME = "yiban_session"


def get_web_user(request: Request, db: Session = Depends(get_db)):
    """从 Cookie 中解析 JWT，返回 User。未登录返回 None（不抛异常）。"""
    token = request.cookies.get(WEB_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
        return db.query(User).filter(User.id == user_id).first()
    except Exception:
        return None


def require_web_user(request: Request, db: Session = Depends(get_db)):
    """Web 页面专用 — 未登录重定向到登录页。"""
    user = get_web_user(request, db)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user

# ============================================================
# Schemas
# ============================================================

class RegisterRequest(BaseModel):
    email: str
    password: str
    phone: str = ""  # 手机号（用于签到，可选）

class LoginRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int

class YibanConfigRequest(BaseModel):
    phone: str
    password: str
    school: str = "福州大学"
    campus: str = "晋江"
    lat: float = 24.571
    lng: float = 118.617
    act: str = "iapp7463"
    client_id: str = "95626fa3080300ea"
    push_key: str = ""

class UserProfile(BaseModel):
    email: str
    phone: str = ""
    tier: str
    expires_at: Optional[datetime] = None
    subscription_active: bool
    has_config: bool
    created_at: datetime

    class Config:
        from_attributes = True

class CheckinLogResponse(BaseModel):
    id: int
    created_at: datetime
    success: bool
    method: str
    message: str

    class Config:
        from_attributes = True

class NotifyRequest(BaseModel):
    title: str
    body: str
    admin_key: str

# ============================================================
# Web Routes (浏览器访问)
# ============================================================

@app.get("/", response_class=HTMLResponse)
def web_index(request: Request, user=Depends(get_web_user)):
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@app.get("/login", response_class=HTMLResponse)
def web_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "user": None})


@app.post("/login")
def web_login_submit(request: Request, email: str = Form(...), password: str = Form(...),
                     db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html",
            {"request": request, "user": None, "error": "邮箱或密码错误"})
    token = create_access_token(user.id)
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie(WEB_COOKIE_NAME, token, max_age=JWT_EXPIRE_DAYS * 86400,
                    httponly=True, samesite="lax")
    return resp


@app.get("/register", response_class=HTMLResponse)
def web_register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "user": None})


@app.post("/register")
def web_register_submit(request: Request, email: str = Form(...), password: str = Form(...),
                        phone: str = Form(""), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html",
            {"request": request, "user": None, "error": "该邮箱已注册"})
    if len(password) < 6:
        return templates.TemplateResponse("register.html",
            {"request": request, "user": None, "error": "密码至少 6 位"})

    user = User(email=email, hashed_password=hash_password(password))
    if phone:
        user.yiban_config = encrypt_config({"phone": phone, "password": "", "school": "",
                                             "campus": "", "lat": 0, "lng": 0, "act": "", "client_id": ""})
    db.add(user)
    db.commit()
    token = create_access_token(user.id)
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie(WEB_COOKIE_NAME, token, max_age=JWT_EXPIRE_DAYS * 86400,
                    httponly=True, samesite="lax")
    return resp


@app.get("/logout")
def web_logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(WEB_COOKIE_NAME)
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def web_dashboard(request: Request, user=Depends(require_web_user), db: Session = Depends(get_db)):
    config = decrypt_config(user.yiban_config)
    from auth import subscription_active
    from monitor import get_daily_stats

    tier_map = {"free": "免费", "monthly": "月付", "yearly": "年付", "lifetime": "永久"}
    profile = {
        "email": user.email,
        "tier": user.tier,
        "tier_display": tier_map.get(user.tier, user.tier),
        "subscription_active": subscription_active(user),
        "has_config": bool(user.yiban_config) and bool(config.get("phone")),
    }

    # 获取用户自己的签到统计
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    today_logs = db.query(CheckinLog).filter(
        CheckinLog.user_id == user.id, CheckinLog.created_at >= today
    ).all()
    month_start = today.replace(day=1)
    month_logs = db.query(CheckinLog).filter(
        CheckinLog.user_id == user.id, CheckinLog.created_at >= month_start
    ).all()

    # 连续签到
    streak = 0
    logs_by_date = {}
    for log in month_logs:
        d = log.created_at.strftime("%Y-%m-%d")
        if d not in logs_by_date or log.success:
            logs_by_date[d] = log.success
    check_date = today
    while True:
        d = check_date.strftime("%Y-%m-%d")
        if logs_by_date.get(d):
            streak += 1
            check_date -= timedelta(days=1)
        elif d == today.strftime("%Y-%m-%d"):
            check_date -= timedelta(days=1)
            continue
        else:
            break

    stats = {
        "today_success": sum(1 for l in today_logs if l.success),
        "today_attempts": len(today_logs),
        "month_success": sum(1 for l in month_logs if l.success),
        "month_total": today.day,
        "streak": streak,
    }

    history = db.query(CheckinLog).filter(
        CheckinLog.user_id == user.id
    ).order_by(CheckinLog.created_at.desc()).limit(20).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user, "profile": profile,
        "stats": stats, "history": history,
    })


@app.post("/dashboard/checkin")
def web_trigger_checkin(request: Request, user=Depends(require_web_user), db: Session = Depends(get_db)):
    if not user.yiban_config:
        return RedirectResponse("/config?error=请先配置签到信息", status_code=302)
    from checkin_worker import run_checkin_for_user
    log = run_checkin_for_user(user)
    db.add(log)
    db.commit()
    success_msg = "签到成功" if log.success else None
    error_msg = None if log.success else log.message
    return RedirectResponse(f"/dashboard?{'success=' + success_msg if success_msg else 'error=' + error_msg}", status_code=302)


@app.get("/config", response_class=HTMLResponse)
def web_config_page(request: Request, user=Depends(require_web_user)):
    cfg = decrypt_config(user.yiban_config)
    return templates.TemplateResponse("config.html", {
        "request": request, "user": user,
        "config": {
            "phone": cfg.get("phone", ""),
            "password": cfg.get("password", ""),
            "school": cfg.get("school", "福州大学"),
            "campus": cfg.get("campus", "晋江"),
            "lat": cfg.get("lat", 24.571),
            "lng": cfg.get("lng", 118.617),
            "act": cfg.get("act", "iapp7463"),
            "client_id": cfg.get("client_id", "95626fa3080300ea"),
            "push_key": user.push_key or "",
        },
    })


@app.post("/config")
def web_config_save(request: Request, user=Depends(require_web_user), db: Session = Depends(get_db),
                    phone: str = Form(...), password: str = Form(...),
                    school: str = Form("福州大学"), campus: str = Form("晋江"),
                    lat: float = Form(24.571), lng: float = Form(118.617),
                    act: str = Form("iapp7463"), client_id: str = Form("95626fa3080300ea"),
                    push_key: str = Form("")):
    config = {"phone": phone, "password": password, "school": school, "campus": campus,
              "lat": lat, "lng": lng, "act": act, "client_id": client_id}
    user.yiban_config = encrypt_config(config)
    user.push_key = push_key
    db.commit()
    return RedirectResponse("/dashboard?success=配置已保存", status_code=302)


@app.get("/history", response_class=HTMLResponse)
def web_history(request: Request, user=Depends(require_web_user), db: Session = Depends(get_db)):
    logs = db.query(CheckinLog).filter(
        CheckinLog.user_id == user.id
    ).order_by(CheckinLog.created_at.desc()).limit(50).all()
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user, "history": logs,
        "profile": {"tier_display": user.tier, "subscription_active": False, "has_config": False},
        "stats": {"today_success": 0, "today_attempts": 0, "month_success": 0, "month_total": 0, "streak": 0},
    })


# ============================================================
# API Routes (macOS App 调用)
# ============================================================

@app.post("/api/register", response_model=TokenResponse)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(status_code=400, detail="该邮箱已注册")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="密码至少 6 位")
    if body.phone and not _valid_phone(body.phone):
        raise HTTPException(status_code=400, detail="手机号格式不正确（11 位数字）")

    user = User(email=body.email, hashed_password=hash_password(body.password))
    # 注册时如果填了手机号，存到 yiban_config 里
    if body.phone:
        user.yiban_config = encrypt_config({"phone": body.phone, "password": "",
                                             "school": "", "campus": "", "lat": 0, "lng": 0,
                                             "act": "", "client_id": ""})
    db.add(user)
    db.commit()
    token = create_access_token(user.id)
    logger.info(f"新用户注册: {body.email}")
    return TokenResponse(access_token=token, user_id=user.id)


@app.post("/api/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="邮箱或密码错误")
    token = create_access_token(user.id)
    return TokenResponse(access_token=token, user_id=user.id)


def _valid_phone(phone: str) -> bool:
    phone = phone.strip()
    return len(phone) == 11 and phone.isdigit() and phone.startswith("1")


# ============================================================
# User endpoints (authenticated)
# ============================================================

@app.get("/api/me", response_model=UserProfile)
def get_profile(user: User = Depends(get_current_user)):
    config = decrypt_config(user.yiban_config)
    return UserProfile(
        email=user.email,
        phone=config.get("phone", ""),
        tier=user.tier,
        expires_at=user.expires_at,
        subscription_active=subscription_active(user),
        has_config=bool(user.yiban_config) and bool(config.get("phone")),
        created_at=user.created_at,
    )


@app.put("/api/me/config")
def update_config(body: YibanConfigRequest, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    config = {
        "phone": body.phone,
        "password": body.password,
        "school": body.school,
        "campus": body.campus,
        "lat": body.lat,
        "lng": body.lng,
        "act": body.act,
        "client_id": body.client_id,
    }
    user.yiban_config = encrypt_config(config)
    user.push_key = body.push_key
    db.commit()
    return {"ok": True}


@app.get("/api/me/history", response_model=list[CheckinLogResponse])
def get_history(user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    logs = (
        db.query(CheckinLog)
        .filter(CheckinLog.user_id == user.id)
        .order_by(CheckinLog.created_at.desc())
        .limit(30)
        .all()
    )
    return logs


@app.post("/api/me/checkin")
def trigger_checkin(user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not user.yiban_config:
        raise HTTPException(status_code=400, detail="请先配置签到信息")
    from checkin_worker import run_checkin_for_user
    log = run_checkin_for_user(user)
    db.add(log)
    db.commit()
    return {"success": log.success, "message": log.message}


@app.post("/api/me/payment-link")
def get_payment_link(user: User = Depends(get_current_user)):
    """生成爱发电支付链接（带 user_id）"""
    plan_id = "your-plan-id"  # 替换为你的爱发电赞助方案 ID
    return {
        "url": f"https://afdian.com/item/{plan_id}?remark=user_id%3D{user.id}",
        "user_id": user.id,
    }

# ============================================================
# Webhook (爱发电)
# ============================================================

@app.post("/api/webhook/afdian")
async def afdian_webhook(request: Request, db: Session = Depends(get_db)):
    """接收爱发电付款通知，自动升级会员"""
    from webhook import handle_order, verify_sign

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="无效的 JSON")

    # 爱发电 webhook 结构: {"data": {"order": {...}}, "sign": "..."}
    data = body.get("data", {})
    order = data.get("order", {})
    sign = body.get("sign", "")

    # 验证签名
    if not verify_sign(data, sign, AFDIAN_TOKEN):
        logger.warning("webhook 签名验证失败")
        raise HTTPException(status_code=403, detail="签名验证失败")

    # 只处理已付款订单
    if order.get("status") != 1:
        return {"ok": True, "message": "订单未付款，跳过"}

    success = handle_order(order, db)
    if success:
        order_no = order.get("out_trade_no", "unknown")
        logger.info(f"✅ webhook 订单处理成功: {order_no}")
        return {"ok": True, "message": "会员已升级"}
    else:
        return {"ok": False, "message": "无法匹配用户"}


# ============================================================
# Admin & Monitoring (protected by simple admin_key)
# ============================================================

_raw_admin = os.environ.get("ADMIN_KEY", "")
if not _raw_admin:
    logger.warning("⚠️ ADMIN_KEY 未设置！管理端点将不可用。请设置环境变量 ADMIN_KEY")
ADMIN_KEY = hashlib.sha256(_raw_admin.encode()).hexdigest()[:16] if _raw_admin else None

def _check_admin(admin_key: str):
    if ADMIN_KEY is None:
        raise HTTPException(status_code=503, detail="管理端点未配置（请设置 ADMIN_KEY 环境变量）")
    if admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="管理密钥错误")


@app.get("/api/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/health/detailed")
def detailed_health(admin_key: str, db: Session = Depends(get_db)):
    """详细健康检查（需要 admin_key）"""
    _check_admin(admin_key)
    from monitor import get_daily_stats, get_failure_alerts
    stats = get_daily_stats(db)
    alerts = get_failure_alerts(db, hours=24)
    return {
        "status": "degraded" if alerts else "ok",
        "stats": stats,
        "failure_alerts": alerts,
    }


@app.get("/api/admin/users")
def list_users(admin_key: str, page: int = 1, size: int = 20, db: Session = Depends(get_db)):
    """管理员查看用户列表"""
    _check_admin(admin_key)
    total = db.query(User).count()
    users = db.query(User).order_by(User.created_at.desc()).offset((page-1)*size).limit(size).all()
    return {
        "total": total, "page": page, "size": size,
        "users": [{
            "id": u.id, "email": u.email, "tier": u.tier,
            "is_active": u.is_active,
            "has_config": bool(u.yiban_config),
            "created_at": u.created_at.isoformat(),
        } for u in users]
    }

@app.get("/api/admin/users/{user_id}")
def get_user_detail(user_id: int, admin_key: str, db: Session = Depends(get_db)):
    """管理员查看用户详情（含签到记录）"""
    _check_admin(admin_key)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    logs = db.query(CheckinLog).filter(CheckinLog.user_id == user_id)\
             .order_by(CheckinLog.created_at.desc()).limit(30).all()
    config = decrypt_config(user.yiban_config)
    return {
        "id": user.id, "email": user.email, "tier": user.tier,
        "is_active": user.is_active, "expires_at": user.expires_at.isoformat() if user.expires_at else None,
        "has_config": bool(user.yiban_config),
        "phone": config.get("phone", "")[:3] + "****" if config.get("phone") else "",
        "school": config.get("school", ""),
        "campus": config.get("campus", ""),
        "created_at": user.created_at.isoformat(),
        "recent_logs": [{"success": l.success, "method": l.method, "message": l.message,
                          "time": l.created_at.isoformat()} for l in logs[:10]],
    }

@app.post("/api/admin/users/{user_id}/toggle")
def toggle_user(user_id: int, admin_key: str, db: Session = Depends(get_db)):
    """管理员启用/禁用用户"""
    _check_admin(admin_key)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    user.is_active = not user.is_active
    db.commit()
    return {"ok": True, "is_active": user.is_active}

@app.post("/api/admin/notify")
def broadcast_notify(body: NotifyRequest, db: Session = Depends(get_db)):
    """向所有付费用户推送通知"""
    _check_admin(body.admin_key)

    import requests as req
    users = db.query(User).filter(
        User.is_active == True,
        User.push_key != None,
        User.push_key != "",
    ).all()

    paid = [u for u in users if subscription_active(u)]
    sent = 0
    for user in paid:
        try:
            req.post(
                f"https://sctapi.ftqq.com/{user.push_key}.send",
                data={"title": body.title, "desp": body.body},
                timeout=5,
            )
            sent += 1
        except Exception:
            pass

    logger.info(f"📢 通知已推送: {sent}/{len(paid)} 付费用户 — {body.title}")
    return {"ok": True, "sent": sent, "total": len(paid)}
