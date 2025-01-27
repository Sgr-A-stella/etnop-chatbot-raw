"""AI chatbot REST endpoint module

This Python file implements REST endpoint for main business functions:
- get (all before request) messages
- get access token (by username and password)
- (JWT authenticated) post last message (for calling external AI chatbot API with last x /by default 10/ messages)

    Running from commandline:
    fastapi dev main.py

"""
from datetime import datetime, timezone, timedelta
from typing import Annotated

import uvicorn
import logging
import jwt

from fastapi import FastAPI, HTTPException
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import Session
from sqlmodel import SQLModel
from pydantic import BaseModel
from pydantic import typing

from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from starlette import status

import mock_AI_chatbot
import nomicAI_GPT4All_caller
import openAI_GPT_API_caller
import settings
from config_loader import load_config

from message_datamodel import Message


DEFAULT_CONVERSATION_MESSAGES_LIMIT = 10
DEFAULT_SYSTEM_MESSAGE = "Hello, how do You do?" # FIXME: need to better context init system message

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: typing.Union[str, None] = None


class User(BaseModel):
    username: str
    email: typing.Union[str, None] = None
    full_name: typing.Union[str, None] = None
    disabled: typing.Union[bool, None] = None

class UserInDB(User):
    hashed_password: str


# FIXME: extract from config
pg_url = "postgresql+psycopg2://postgres:postgres@localhost:5432/chatbot_messages"
connect_args = {"check_same_thread": False}
engine = create_engine(pg_url)

config = load_config()



def create_db_and_tables():
    logger.info("DB connection: " + pg_url)
    logger.info("Create all missed (!) DB objects by engine and SQLModel metadata...")
    SQLModel.metadata.create_all(engine)


def get_session():
    logger.info("Engine database: " + engine.url.database)
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


app = FastAPI(title='chatbot')
logger = logging.getLogger('uvicorn.error')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


if __name__ == '__main__':
    uvicorn.run(app, log_config=settings.LOGGING_CONFIG)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: typing.Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
        current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



@app.on_event("startup")
def on_startup():
    logger.info("Startup...")
    create_db_and_tables()


# somke test endpoints

@app.get("/")
async def root():
    logger.info('GET root')
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    logger.info('GET hello with name: ' + name)
    return {"message": f"Hello {name}"}


# from this business endpoints

@app.post("/message")
async def create_message(message: Message, session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]) -> Message:
    logger.info("Create message...")

    # assume, that empty role is user and system role included in message sent from client always
    if message.role is None:
        message.role = openAI_GPT_API_caller.USER_ROLE
    message.create_time = datetime.now()
    session.add(message)
    session.commit()
    session.refresh(message)

    # FIXME: from this logic OpenAI GPT API specific - refactor to there!
    messages = session.query(Message)\
        .order_by(desc(Message.create_time))\
        .where(Message.username == message.username and Message.role != openAI_GPT_API_caller.SYSTEM_ROLE)\
        .limit(DEFAULT_CONVERSATION_MESSAGES_LIMIT)\
        .all()
    logger.info(f"Messages count: {len(messages)}")
    conversation_messages = [msg.message_text for msg in messages]

    # NOTE: what if last system message after first conversation message...? (prefix of conversation is out of context!)
    sys_msg = session.query(Message) \
        .order_by(desc(Message.create_time)) \
        .where(Message.username == message.username and Message.role != openAI_GPT_API_caller.SYSTEM_ROLE) \
        .limit(1) \
        .all()
    logger.info(f"System message count: {len(sys_msg)}")
    system_message = DEFAULT_SYSTEM_MESSAGE if sys_msg is None else sys_msg[0].message_text

    #response_message_text = openAI_GPT_API_caller.call_GPT_API_chat_completion_with_message_response(
    #    system_message, conversation_messages)
    #response_message_text = nomicAI_GPT4All_caller.generate_response(message.message_text, None)
    #response_message_text = mock_AI_chatbot.call_GPT_API_chat_completion_with_message_response(
    #    system_message, conversation_messages, None)
    response_message_text = mock_AI_chatbot.generate_response(message.message_text, None)
    # FIXME: to this logic OpenAI GPT API specific - refactor to there!

    response_message = Message()
    response_message.message_text = response_message_text
    response_message.username = message.username
    response_message.role = openAI_GPT_API_caller.ASSISTANT_ROLE
    response_message.create_time = datetime.now()

    session.add(response_message)
    session.commit()
    session.refresh(response_message)

    return response_message


@app.get("/messages")
async def read_messages(
        session: SessionDep,
        user: str = None,
        offset: int = 0,
        limit: int = 100,
) -> list[Message]:
    logger.info("Read messages...")
    if user == None:
        messages = session.query(Message).offset(offset).limit(limit).all()
    else:
        logger.info("for user: " + user)
        messages = session.query(Message).where(Message.username == user).offset(offset).limit(limit).all()
    return messages


@app.get("/message/{message_id}")
async def read_message(message_id: int, session: SessionDep) -> Message:
    logger.info("Get message...")
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    return message


@app.delete("/message/{message_id}")
async def delete_message(message_id: int, session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]):
    logger.info("Delete message...")
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    session.delete(message)
    session.commit()
    return {"ok": True}


@app.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")
