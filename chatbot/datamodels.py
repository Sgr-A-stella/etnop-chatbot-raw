"""Message data model module

FIXME: logic for Message only, missing logic for User
"""

from datetime import datetime

from pydantic import typing
from sqlmodel import Field, SQLModel


class Message(SQLModel, table=True):
    __tablename__ = 'chatbot_message'
    id: typing.Union[int, None] = Field(default=None, primary_key=True)
    # FIXME: logic (endpoint /register, login,... etc./ and CRUD/persistence) refactor for using foreign key
    #user_id: typing.Union[int, None] = Field(default=None, foreign_key='chatbot_user.id')
    # FIXME: business id reference to table/model chatbot_user/User without foreign key (present logic requires this)
    username: str = Field(index=True)
    role: str = Field(index=True)
    message_text: str
    create_time: datetime


class User(SQLModel, table=True):
    __tablename__ = 'chatbot_user'
    id: typing.Union[int, None] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    full_name: str = Field(index=True)
    email: str = Field(index=True, unique=True)
    hashed_pw: str
    disabled: bool
    last_login: datetime
