import re
from typing import Final

from fastapi import HTTPException, status

SQLI_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(--|/\*|\*/|;|'|\"|\bOR\b\s+\d+=\d+|\bUNION\b|\bSELECT\b.*\bFROM\b|\bDROP\b|\bINSERT\b|\bUPDATE\b)",
    re.IGNORECASE,
)


def block_sql_injection_payload(user_text: str) -> None:
    if SQLI_PATTERN.search(user_text):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Input blocked by SQL injection defense layer.",
        )
