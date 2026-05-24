from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=255)
    secret_note: str = Field(min_length=1, max_length=500)


class RegisterResponse(BaseModel):
    record_id: int
    message: str


class CapabilityIssueRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    permission: str = Field(default="read")
    ttl_seconds: int = Field(default=900, ge=60, le=86400)


class CapabilityIssueResponse(BaseModel):
    capability_code: str
    expires_in_seconds: int


class SecureFetchRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    capability_code: str = Field(min_length=20)


class SecureFetchResponse(BaseModel):
    username: str
    email: str
    secret_note: str
