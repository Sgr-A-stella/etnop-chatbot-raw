"""Message data model module

...

"""
from datetime import datetime

from pydantic import typing
from sqlmodel import Field, SQLModel, Column, Integer


class Message(SQLModel, table=True):
    __tablename__ = 'message'
    id: typing.Union[int, None] = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    role: str = Field(index=True)
    message_text: str
    create_time: datetime
