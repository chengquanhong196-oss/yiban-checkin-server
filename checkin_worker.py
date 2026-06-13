"""
Daily batch check-in worker.
Iterates all active users, decrypts their credentials, runs the yiban API flow.
This is the same API flow as cloud_checkin.py but integrated into the server.
"""

import json
import time
import base64
import hashlib
import urllib.parse
import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from sqlalchemy.orm import Session

from models import SessionLocal, User, CheckinLog
from auth import decrypt_config
from config import PUSH_ENABLED

logger = logging.getLogger("checkin_worker")

# ============================================================
# RSA encryption (same as cloud_checkin.py)
# ============================================================

RSA_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzq0rgsM++ZxLRGHpdfre
Hu6UXhdlUS5P2WOxRG14qU8/iWSb/CkOqgOl8AGcOhlthkvolCdpUvVcVsVUxBv0
YRN0Jb64zPrn5aLVwQT4RJn5tXvoqLdHIXis7pljXAMDPVZOVlWJkDMk8YU6HDaA
MqsD6l5p9lg2LMP4OhMgaPX+CkO370LB5vRjJTHp03n+IqfxXoC7DEd+kxRIEM2C
EDgUSYDJBDgwBvGALZmvB/a1b0im9t1P/EmnuE7uN9NRFoWyVpOiEwo/Ti7rmJGf
qNT3vvtfWo4nXsm1rYQXsPayoKDSRaba3gFY/1SYWLAuSO2q2da5ZCcsAk5RKy0V
c1hUg8n6y0YLAvuzoXY5VyNMXkhH5Zc5Kg64b5RxILeZpZG0MV7GFY3sw//k7SNg
darKT8A0Iv3l3lfguX3HNi6dkf97kS/EiA0tbkIB/JNjv13mq8HL7LijRt2hkKqP
PhQW88xC/exZilU5pAavoZOPuZIOTUHqtpRq4ZeKl+wDf+e5lPYFDpihWGjplGpa
4BOSmGeo/SyVFPji9QF4Pk0DRJF/NjwJoAC60xHAVt5Z4gQSOOOjNZDCswA0ry2L
e8m5cv5vPGY75uVrGqALQ6Xm961PPc5cJ1q7tmEZMj+z5HE7tgAdhiPI6acKgrAv
+1k4N0OVqKamMS+PVpD05hUCAwEAAQ==
-----END PUBLIC KEY-----"""


def rsa_encrypt(text: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_pem_public_key(RSA_PUBKEY.encode(), password=None)
    encrypted = key.encrypt(text.encode("utf-8"), padding.PKCS1v15())
    return base64.b64encode(encrypted).decode()


# ============================================================
# Yiban API (exact same flow as cloud_checkin.py)
# ============================================================

UA = "Yiban"
APP_VERSION = "5.1.2"


def _push_to_phone(push_key: str, title: str, body: str):
    if not push_key or not PUSH_ENABLED:
        return
    try:
        requests.post(
            f"https://sctapi.ftqq.com/{push_key}.send",
            data={"title": title, "desp": body},
            timeout=5,
        )
    except Exception:
        pass


def run_checkin_for_user(user: User) -> CheckinLog:
    """Execute yiban evening check-in for a single user. Returns a CheckinLog."""
    config = decrypt_config(user.yiban_config)
    phone = config.get("phone", "")
    password = config.get("password", "")
    lat = float(config.get("lat", 24.571))
    lng = float(config.get("lng", 118.617))
    school = config.get("school", "福州大学")
    campus = config.get("campus", "晋江")
    act = config.get("act", "iapp7463")
    client_id = config.get("client_id", "95626fa3080300ea")

    if not phone or not password:
        return CheckinLog(user_id=user.id, success=False, method="cloud",
                          message="未配置手机号或密码")

    session = requests.Session()
    session.headers.update({"User-Agent": UA, "AppVersion": APP_VERSION})
    for domain in ["api.uyiban.com", "c.uyiban.com", ".uyiban.com"]:
        session.cookies.set("csrf_token", "00000", domain=domain)

    encrypted = rsa_encrypt(password)
    access_token = ""

    # —— Login ——
    logged_in = False
    for identify in ["1", "0"]:
        resp = session.post(
            "https://m.yiban.cn/api/v4/passport/login",
            data={"ct": "2", "identify": identify, "mobile": phone, "password": encrypted},
        )
        data = resp.json()
        if data.get("response") != 100:
            if data.get("response") in (200, 201, 202, 210):
                return CheckinLog(user_id=user.id, success=False, method="cloud",
                                  message=f"登录失败: {data.get('data', {}).get('message', '密码错误')}")
            continue
        token = data.get("data", {}).get("access_token", "")
        if not token:
            continue
        access_token = token

        # Get verify_request
        vr_headers = {"Authorization": f"Bearer {token}", "logintoken": token,
                      "Origin": "https://c.uyiban.com", "User-Agent": UA, "AppVersion": APP_VERSION}
        vr_resp = requests.get(f"https://f.yiban.cn/iapp/index?act={act}",
                               headers=vr_headers, allow_redirects=False)
        location = vr_resp.headers.get("Location", "")
        if "verify_request=" not in location:
            continue
        verify = location.split("verify_request=", 1)[-1].split("&")[0]

        # CAS OAuth
        base_h = {"Origin": "https://c.uyiban.com", "User-Agent": UA, "AppVersion": APP_VERSION}
        redirect_uri = f"https://f.yiban.cn/{act}"
        session.get(f"https://api.uyiban.com/base/c/auth/yiban?verifyRequest={verify}&CSRF=00000", headers=base_h)
        session.get(f"https://oauth.yiban.cn/code/html?client_id={client_id}&redirect_uri={redirect_uri}", headers=base_h)
        session.post("https://oauth.yiban.cn/code/usersure",
                     data={"client_id": client_id, "redirect_uri": redirect_uri}, headers=base_h)
        r4 = session.get(f"https://api.uyiban.com/base/c/auth/yiban?verifyRequest={verify}&CSRF=00000", headers=base_h)
        if r4.json().get("code") == 0:
            logged_in = True
            break

    if not logged_in:
        return CheckinLog(user_id=user.id, success=False, method="cloud",
                          message="登录流程失败")

    # —— Get sign range ——
    resp = session.get(
        "https://api.uyiban.com/nightAttendance/student/index/signPosition?CSRF=00000",
        headers={"Origin": "https://c.uyiban.com", "User-Agent": UA, "AppVersion": APP_VERSION},
    )
    data = resp.json()
    if data.get("code") != 0:
        return CheckinLog(user_id=user.id, success=False, method="cloud",
                          message=f"获取签到时段失败: {data.get('msg', '')}")

    rng = data.get("data", {}).get("Range", {})
    now = time.time()
    if now < rng.get("StartTime", 0) or now > rng.get("EndTime", 0):
        return CheckinLog(user_id=user.id, success=False, method="cloud",
                          message="不在签到时段")

    # —— Submit sign-in ——
    sign_info = json.dumps({
        "Reason": "", "AttachmentFileName": "",
        "LngLat": f"{lng},{lat}",
        "Address": f"{school}{campus}校区",
    })
    resp = session.post(
        "https://api.uyiban.com/nightAttendance/student/index/signIn?CSRF=00000",
        data={"Code": "", "PhoneModel": "", "SignInfo": sign_info, "OutState": "1"},
        headers={"Origin": "https://c.uyiban.com", "User-Agent": UA, "AppVersion": APP_VERSION},
    )
    result = resp.json()

    if result.get("code") == 0:
        _push_to_phone(user.push_key, "✅ 云签到成功",
                        f"{datetime.now(timezone.utc).strftime('%H:%M')} 晚点签到完成")
        return CheckinLog(user_id=user.id, success=True, method="cloud",
                          message="签到成功")
    else:
        msg = result.get("msg", "未知错误")
        _push_to_phone(user.push_key, "❌ 云签到失败", msg)
        return CheckinLog(user_id=user.id, success=False, method="cloud",
                          message=msg)


# ============================================================
# Batch runner
# ============================================================

def run_daily_checkin():
    """Run check-in for all active users. Called by the scheduler."""
    logger.info("========== 每日批量签到开始 ==========")
    db = SessionLocal()
    try:
        users = db.query(User).filter(User.is_active == True).all()
        logger.info(f"活跃用户数: {len(users)}")

        success_count = 0
        for user in users:
            logger.info(f"签到: {user.email}")
            try:
                log = run_checkin_for_user(user)
                db.add(log)
                # Log is not yet committed, but we need user from db
                # Reload the user to attach the log properly
            except Exception as e:
                logger.error(f"签到异常 ({user.email}): {e}")
                db.add(CheckinLog(user_id=user.id, success=False, method="cloud",
                                  message=f"系统异常: {str(e)[:500]}"))
            else:
                if log.success:
                    success_count += 1

        db.commit()
        logger.info(f"批量签到完成: {success_count}/{len(users)} 成功")
    finally:
        db.close()
