"""User module for user management

TODO: mock DB logic only, missed RDBMS logic
"""
from typing import Annotated
import logging

from fastapi import HTTPException
from fastapi.params import Depends

from pydantic import BaseModel
from pydantic import typing

import oauth2_token
from oauth2_token import oauth2_scheme, verify_password, get_username_from_token
from mock_datastore import fake_users_db

from business_exception import credentials_exception

logger = logging.getLogger('uvicorn.error')

class User(BaseModel):
    username: str
    full_name: typing.Union[str, None] = None
    email: typing.Union[str, None] = None
    disabled: typing.Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        logger.info(user_dict)
        return UserInDB(**user_dict)



def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    username: str = get_username_from_token(token)
    user = get_user(fake_users_db, username=username)
    if user is None:
        raise credentials_exception
    return user


def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_new_user(db, username: str, password: str, email: str, full_name: str):
    if username in db:
        raise HTTPException(status_code=400, detail="Exist user")
    hashed_password = oauth2_token.get_password_hash(password)
    user_in_db = UserInDB(username=username, full_name=full_name, email=email, disabled=False, hashed_password=hashed_password)
    print(user_in_db.model_dump(mode='json'))
    db.update({username: user_in_db.model_dump(mode='json')})
    logger.info(db)
    return authenticate_user(db, username, password)
