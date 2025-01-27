"""Business exception module for application specific business exceptions"""

from fastapi import HTTPException
from starlette import status


"""Credential exception for authentication errors"""
credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"}
)
