from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key")

API_KEYS = {
    "test_api_key": "test_user"
}


def get_current_user(api_key: str = Depends(api_key_header)):
    print("api_key: " + api_key)
    if api_key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return API_KEYS[api_key]
