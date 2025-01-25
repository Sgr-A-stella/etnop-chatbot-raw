"""Message data model module

...

"""
from datetime import datetime

from pydantic import typing
from sqlmodel import Field, Session, SQLModel, create_engine, select


class Message(SQLModel, table=True):
    id: typing.Union[int, None] = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    message_text: str
    create_time: datetime
