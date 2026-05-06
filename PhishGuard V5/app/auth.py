import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer

SECRET = "supersecurekey"
security = HTTPBearer()

def verify(token=Depends(security)):
    try:
        jwt.decode(token.credentials, SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid token")

// @router.post("/domain", dependencies=[Depends(verify)])