"""User module for user management"""

from typing import Annotated

from fastapi import HTTPException
from fastapi.params import Depends

from pydantic import BaseModel
from pydantic import typing

from oauth2_token import oauth2_scheme, verify_password, get_username_from_token  # , TokenData
from mock_datastore import fake_users_db

from business_exception import credentials_exception


class User(BaseModel):
    username: str
    email: typing.Union[str, None] = None
    full_name: typing.Union[str, None] = None
    disabled: typing.Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)



def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    username: str = get_username_from_token(token)
    #token_data = TokenData(username=username)
    #user = get_user(fake_users_db, username=token_data.username)
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
