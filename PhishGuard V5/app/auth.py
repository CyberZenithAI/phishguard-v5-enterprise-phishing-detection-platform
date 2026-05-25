# app/auth.py

from datetime import datetime, timedelta

import jwt

from fastapi import Header, HTTPException

from app.core.config import settings


def create_token(username: str):

    payload = {
        "sub": username,
        "exp": datetime.utcnow()
        + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        ),
    }

    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


async def verify(authorization: str = Header(None)):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="missing_authorization_header",
        )

    try:

        token = authorization.replace("Bearer ", "")

        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )

        return payload

    except jwt.ExpiredSignatureError:

        raise HTTPException(
            status_code=401,
            detail="token_expired",
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail="invalid_token",
        )
