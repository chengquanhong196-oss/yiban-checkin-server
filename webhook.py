"""
爱发电 Webhook — 用户付款后自动升级会员 tier + expires_at

爱发电 webhook 文档: https://afdian.com/p/9c65d9cc6d6711ec9d5252540025c377

配置:
  AFDIAN_TOKEN — 爱发电 API token（在爱发电开发者页面获取）
  AFDIAN_USER_ID — 你的爱发电 user_id
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from config import AFDIAN_TOKEN
from models import User

logger = logging.getLogger("webhook")


def verify_sign(data: dict, sign: str, token: str) -> bool:
    """验证爱发电 webhook 签名"""
    if not token:
        logger.error("AFDIAN_TOKEN 未配置，webhook 签名验证已跳过——生产环境必须配置！")
        return True  # 开发环境兼容
    # 按 key 排序后拼接，加上 token 做 MD5
    sorted_keys = sorted(data.keys())
    raw = "".join(f"{k}{data[k]}" for k in sorted_keys if k != "sign")
    raw += token
    expected = hashlib.md5(raw.encode()).hexdigest()
    return sign == expected


def handle_order(order: dict, db: Session) -> bool:
    """
    处理一笔爱发电订单。
    order 结构:
      {
        "out_trade_no": "20240101...",   # 订单号
        "total_amount": "6.90",          # 金额
        "remark": "user_id=42",          # 用户备注（包含 user_id）
        "plan_id": "...",                # 赞助方案 ID
        "month": 1,                      # 月数
      }
    返回 True 表示升级成功。
    """
    remark = order.get("remark", "")
    amount = float(order.get("total_amount", 0))
    months = int(order.get("month", 1))

    # 从 remark 中提取 user_id: "user_id=42"
    user_id = _extract_user_id(remark)
    if not user_id:
        logger.warning(f"无法从备注提取 user_id: {remark}")
        return False

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        logger.warning(f"用户不存在: {user_id}")
        return False

    tier, expires_at = _calculate_subscription(user, amount, months)
    user.tier = tier
    user.expires_at = expires_at
    db.commit()

    logger.info(f"✅ 会员升级: {user.email} → {tier}, 到期 {expires_at}")
    return True


def _extract_user_id(remark: str) -> Optional[int]:
    """从备注中提取 user_id。支持格式: 'user_id=42' 或 'uid=42'"""
    if not remark:
        return None
    for prefix in ("user_id=", "uid="):
        if prefix in remark:
            parts = remark.split(prefix, 1)[-1].split(",")[0].split("&")[0].split(" ")[0]
            try:
                return int(parts.strip())
            except ValueError:
                pass
    # 尝试直接解析整个 remark 为数字
    try:
        return int(remark.strip())
    except ValueError:
        pass
    return None


def _calculate_subscription(user: User, amount: float, months: int) -> tuple:
    """
    根据金额和月数计算会员等级和到期时间。
    定价参考:
      月付 ¥6.9  → 1 个月 → monthly
      年付 ¥49   → 12 个月 → yearly
      永久 ¥99   → 999 个月 → lifetime
    """
    now = datetime.now(timezone.utc)

    if amount >= 90 or months >= 99:
        return ("lifetime", None)  # 永久会员

    if amount >= 35 or months >= 6:
        # 年付/半年付
        tier = "yearly"
        duration = max(months, 12)
    else:
        # 月付
        tier = "monthly"
        duration = max(months, 1)

    # 如果当前已是会员，从当前到期日续
    if user.expires_at and user.expires_at > now and user.tier == tier:
        start = user.expires_at
    else:
        start = now

    expires_at = start + timedelta(days=duration * 31)
    return (tier, expires_at)
