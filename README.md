# CodeAlpha_Detecting-Data-Leaks-Using-SQL-Injection
# Detecting Data Leaks Using SQL Injection

This project is a lightweight cloud-ready API that protects sensitive user data from SQL injection-driven leaks.

## Security Model

The system uses **double-layer defense**:

1. **SQL Injection Detection Layer**
   - input payload filtering for common SQL injection signatures
   - strict request validation
2. **Safe Query Execution Layer**
   - parameterized ORM queries (no string-concatenated SQL)
   - capability-code authorization before secure reads

Additionally, all sensitive fields are encrypted at rest with **AES-256-GCM**.

## Features

- AES-256 encryption for email, password, and secret notes
- Capability code mechanism (HMAC-SHA256 signed, expiring token) to control server access
- SQL injection pattern blocking middleware and endpoint validation
- Security audit trail for critical actions
- Works with SQLite by default (very low system requirements)
- Internet-accessible via FastAPI + Uvicorn

## Project Structure

```text
app/
  main.py          # API routes and middleware
  config.py        # environment configuration
  database.py      # SQLAlchemy engine/session
  models.py        # secure_records and security_audit tables
  crypto.py        # AES-256-GCM encryption/decryption
  capability.py    # capability code generation/verification
  security.py      # SQL injection detection layer
  schemas.py       # request/response models
requirements.txt
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional environment file:

```env
APP_SECRET=change-this-to-a-long-random-value
DATABASE_URL=sqlite:///./secure_vault.db
# Optional explicit AES-256 key in hex (64 hex chars)
MASTER_KEY_HEX=
```

## Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Now the API is reachable over the internet when deployed on any small VM/container with port 8000 exposed.

## API Flow

1. Register encrypted data

```bash
curl -X POST "http://127.0.0.1:8000/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"alice",
    "email":"alice@example.com",
    "password":"super-secure-password",
    "secret_note":"salary details"
  }'
```

2. Issue capability code

```bash
curl -X POST "http://127.0.0.1:8000/capability/issue" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"alice",
    "permission":"read",
    "ttl_seconds":900
  }'
```

3. Secure fetch using capability code

```bash
curl -X POST "http://127.0.0.1:8000/secure/fetch" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"alice",
    "capability_code":"<PASTE_CODE>"
  }'
```

## Why this meets your requirements

- **SQL injection leak prevention:** two independent defenses before data is returned.
- **AES-256 protection:** sensitive data is encrypted before DB write.
- **Capability access control:** secure, signed, expiring capability codes gate reads.
- **Cloud accessibility:** FastAPI service runs on low-resource machines and can be deployed publicly.
