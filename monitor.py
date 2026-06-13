"""
监控模块 — 签到统计 + 失败告警 + 健康检查
"""

import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func

from models import SessionLocal, User, CheckinLog

logger = logging.getLogger("monitor")


def get_daily_stats(db: Session) -> dict:
    """获取今日签到统计"""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    total_users = db.query(User).filter(User.is_active == True).count()
    paid_users = db.query(User).filter(
        User.is_active == True,
        User.tier.in_(["monthly", "yearly", "lifetime"])
    ).count()

    today_logs = (
        db.query(CheckinLog)
        .filter(CheckinLog.created_at >= today)
        .all()
    )
    success = sum(1 for l in today_logs if l.success)
    failed = len(today_logs) - success

    return {
        "total_users": total_users,
        "paid_users": paid_users,
        "today_attempts": len(today_logs),
        "today_success": success,
        "today_failed": failed,
        "success_rate": f"{success / max(len(today_logs), 1) * 100:.1f}%",
    }


def get_failure_alerts(db: Session, hours: int = 24) -> list[dict]:
    """获取最近 N 小时内签到连续失败的用户（告警用）"""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # 查询最近 24 小时内有签到记录但全部失败的用户
    users_with_failures = (
        db.query(User.id, User.email)
        .join(CheckinLog)
        .filter(CheckinLog.created_at >= since)
        .group_by(User.id)
        .having(func.sum(CheckinLog.success) == 0)  # 没有一次成功
        .all()
    )

    alerts = []
    for user_id, email in users_with_failures:
        recent_failures = (
            db.query(CheckinLog)
            .filter(
                CheckinLog.user_id == user_id,
                CheckinLog.created_at >= since,
                CheckinLog.success == False,
            )
            .order_by(CheckinLog.created_at.desc())
            .limit(5)
            .all()
        )
        alerts.append({
            "user_id": user_id,
            "email": email,
            "failure_count": len(recent_failures),
            "latest_error": recent_failures[0].message if recent_failures else "",
        })

    return alerts


def check_and_alert():
    """定时检查：连续失败的用户 → 打印日志（未来可接 Server酱/邮件）"""
    db = SessionLocal()
    try:
        alerts = get_failure_alerts(db, hours=24)
        if alerts:
            logger.warning(f"⚠️ 签到异常用户: {len(alerts)} 人")
            for a in alerts[:10]:
                logger.warning(f"  {a['email']}: {a['failure_count']}次失败 — {a['latest_error'][:80]}")
    finally:
        db.close()
