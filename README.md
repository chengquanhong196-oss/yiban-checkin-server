# yiban-checkin-server

易班云签到后端服务。支持 macOS App、Web 浏览器、API 调用。

## 快速部署

```bash
pip install -r requirements.txt

export JWT_SECRET=$(openssl rand -hex 32)
export CREDENTIAL_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export ADMIN_KEY="your-admin-password"

uvicorn main:app --host 0.0.0.0 --port 8000
```

## Docker

```bash
docker build -t yiban-server .
docker run -d -p 8000:8000 \
  -e JWT_SECRET=<随机密钥> \
  -e CREDENTIAL_ENCRYPTION_KEY=<Fernet密钥> \
  -e ADMIN_KEY=<管理密码> \
  -e AFDIAN_TOKEN=<爱发电token> \
  -v ./data:/app/data \
  yiban-server
```

## Web 面板

- `/` — 首页 + 定价
- `/register` — 注册
- `/login` — 登录
- `/dashboard` — 控制台（签到统计、手动签到、升级会员）
- `/config` — 签到配置（学校、坐标、易班账号）
- `/history` — 签到记录

## API（macOS App 用）

| 端点 | 说明 |
|------|------|
| POST /api/register | 注册 |
| POST /api/login | 登录 → JWT |
| GET /api/me | 用户信息 |
| PUT /api/me/config | 更新签到配置 |
| GET /api/me/history | 签到历史 |
| POST /api/me/checkin | 手动签到 |
| POST /api/me/payment-link | 获取支付链接 |

## 管理

| 端点 | 说明 |
|------|------|
| GET /api/health | 基本健康检查 |
| GET /api/health/detailed?admin_key=xxx | 详细统计 + 异常用户 |
| POST /api/admin/notify | 批量推送通知给付费用户 |
| POST /api/webhook/afdian | 爱发电付款回调 |

## 环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| JWT_SECRET | ✅ | JWT 签名密钥 |
| CREDENTIAL_ENCRYPTION_KEY | ✅ | Fernet 加密密钥 |
| ADMIN_KEY | — | 管理面板密码 |
| AFDIAN_TOKEN | — | 爱发电 webhook token |
| DATABASE_URL | — | SQLite 默认 |
