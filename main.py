from fastapi import Depends, FastAPI, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .capability import generate_capability_code, verify_capability_code
from .crypto import decrypt_field, encrypt_field
from .database import Base, engine, get_db
from .models import SecureRecord, SecurityAudit
from .schemas import (
    CapabilityIssueRequest,
    CapabilityIssueResponse,
    RegisterRequest,
    RegisterResponse,
    SecureFetchRequest,
    SecureFetchResponse,
)
from .security import block_sql_injection_payload

app = FastAPI(
    title="Detecting Data Leaks Using SQL Injection Defense",
    description="Cloud-ready lightweight API with AES-256 encryption + capability access codes + SQLi defenses.",
    version="1.0.0",
)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


def log_event(db: Session, event: str, details: str) -> None:
    db.add(SecurityAudit(event=event, details=details))
    db.commit()


@app.middleware("http")
async def generic_sqli_input_filter(request: Request, call_next):
    query_text = str(request.url.query)
    if query_text:
        block_sql_injection_payload(query_text)
    response = await call_next(request)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register", response_model=RegisterResponse)
def register(request: RegisterRequest, db: Session = Depends(get_db)) -> RegisterResponse:
    # Layer 1: request-level SQLi pattern filter
    block_sql_injection_payload(request.username)
    block_sql_injection_payload(request.email)
    block_sql_injection_payload(request.secret_note)

    existing = db.scalar(select(SecureRecord).where(SecureRecord.username == request.username))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")

    record = SecureRecord(
        username=request.username,
        email_encrypted=encrypt_field(request.email),
        password_encrypted=encrypt_field(request.password),
        secret_note_encrypted=encrypt_field(request.secret_note),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    log_event(db, "register", f"New record created for username={request.username}")
    return RegisterResponse(record_id=record.id, message="Stored using AES-256 encryption.")


@app.post("/capability/issue", response_model=CapabilityIssueResponse)
def issue_capability(request: CapabilityIssueRequest, db: Session = Depends(get_db)) -> CapabilityIssueResponse:
    block_sql_injection_payload(request.username)
    record = db.scalar(select(SecureRecord).where(SecureRecord.username == request.username))
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown username.")

    code = generate_capability_code(
        username=request.username,
        permission=request.permission,
        ttl_seconds=request.ttl_seconds,
    )
    log_event(db, "capability_issue", f"Issued capability for username={request.username}")
    return CapabilityIssueResponse(capability_code=code, expires_in_seconds=request.ttl_seconds)


@app.post("/secure/fetch", response_model=SecureFetchResponse)
def secure_fetch(request: SecureFetchRequest, db: Session = Depends(get_db)) -> SecureFetchResponse:
    block_sql_injection_payload(request.username)
    try:
        context = verify_capability_code(request.capability_code, required_permission="read")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    if context.username != request.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Capability does not belong to the requested username.",
        )

    # Layer 2: no string-formatted SQL at all; use parameterized ORM query
    record = db.scalar(select(SecureRecord).where(SecureRecord.username == request.username))
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record not found.")

    log_event(db, "secure_fetch", f"Read by capability for username={request.username}")
    return SecureFetchResponse(
        username=record.username,
        email=decrypt_field(record.email_encrypted),
        secret_note=decrypt_field(record.secret_note_encrypted),
    )
