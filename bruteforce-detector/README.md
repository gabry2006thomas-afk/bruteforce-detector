# 🛡️ SecureGuard — Brute Force Detection System

A full-stack cybersecurity tool that detects and blocks brute-force login attacks in real time.

---

## Features

| Feature | Details |
|---|---|
| **User Auth** | Register, login, logout with bcrypt-hashed passwords |
| **Brute Force Detection** | Blocks after 5 failed attempts within 10 minutes |
| **IP Blocking** | Automatic 15-minute IP block on threshold breach |
| **Account Locking** | Per-email lockout with remaining-time feedback |
| **Security Logging** | All events written to `logs/security.log` |
| **Admin Dashboard** | Live stats, attempt table, block list, hourly chart |
| **Attack Simulator** | Inject fake attempts to test detection logic |

---

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Visit `http://127.0.0.1:5000`

---

## Database Schema

```sql
CREATE TABLE users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,           -- bcrypt hash
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    status     TEXT NOT NULL,           -- 'success' | 'failed'
    reason     TEXT,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_entities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity      TEXT NOT NULL,          -- IP or email
    entity_type TEXT NOT NULL,          -- 'ip' | 'email'
    blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    unblock_at  DATETIME NOT NULL,
    reason      TEXT
);
```

---

## Detection Logic

```
IF failed_attempts(email, last 10 min) >= 5  →  lock account for 15 min
IF failed_attempts(ip,    last 10 min) >= 5  →  block IP for 15 min
```

Every failed login decrements an on-screen "attempts remaining" counter.
At ≤2 attempts the UI shows a warning. On lockout, exact remaining minutes are returned.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/register` | Create new account |
| POST | `/api/login` | Authenticate + brute-force check |
| POST | `/api/logout` | Invalidate session |
| GET  | `/api/admin/stats` | Full stats, attempts, blocks |
| POST | `/api/simulate` | Inject simulated attack attempts |

---

## Security Practices

- Passwords hashed with **bcrypt** (salted, never stored plaintext)
- No credentials hardcoded anywhere
- All inputs validated and sanitised
- Session secret generated with `os.urandom(32)` at startup
- DB errors handled gracefully — system never crashes
- IP captured via `X-Forwarded-For` with fallback to `remote_addr`

---

## Log Format

```
2025-01-01 12:00:00 | WARNING | [LOGIN_FAILED] {"email": "x@x.com", "ip": "1.2.3.4"}
2025-01-01 12:00:05 | WARNING | [BLOCKED] {"entity": "1.2.3.4", "type": "ip", ...}
```

Events logged: `REGISTER`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `BLOCKED`, `BLOCKED_ATTEMPT`, `LOGOUT`, `SIMULATION`, `SYSTEM`
