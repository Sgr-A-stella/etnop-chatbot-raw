"""Token module for token management"""

from datetime import timedelta, datetime, timezone
from typing import Annotated

import jwt

from fastapi.params import Depends
from fastapi.security import OAuth2PasswordBearer
from jwt import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from pydantic import typing

import config_loader
from business_exception import credentials_exception


# to get a string like this run:
# openssl rand -hex 32
DEFAULT_SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
DEFAULT_ALGORITHM = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 30

token_config = config_loader.load_config(section="token")

# use config or default values
SECRETKEY_KEY = "secretkey"
secret_key = token_config[SECRETKEY_KEY] if token_config[SECRETKEY_KEY] is not None else DEFAULT_SECRET_KEY
ALGORITHM_KEY = "algorithm"
algorithm = token_config[ALGORITHM_KEY] if token_config[ALGORITHM_KEY] is not None else DEFAULT_ALGORITHM
EXPIRE_KEY = "expire"
access_token_expire_minutes = int(token_config[EXPIRE_KEY]) if token_config[EXPIRE_KEY] is not None \
    else DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: typing.Union[str, None] = None


def create_access_token(data: dict):
    expires_delta: typing.Union[timedelta, None] = timedelta(minutes=access_token_expire_minutes)
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_username_from_token(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception

        return username
    except InvalidTokenError:
        raise credentials_exception
