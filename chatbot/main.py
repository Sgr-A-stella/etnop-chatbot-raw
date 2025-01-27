"""AI chatbot REST endpoint module

This Python file implements REST endpoint for main business functions:
- get (all before request or last limited number and/or given user's) messages
- get one message by id
- register user (and login)
- login and get access token (by username and password)
- logout (cleanup and invalidate token)
- (JWT authenticated) post last message (for calling external AI chatbot API with last x /by default 10/ messages)
- delete one message by id

    Running from commandline:
    fastapi dev main.py

"""

from datetime import datetime
from typing import Annotated

import uvicorn
import logging

from fastapi import FastAPI, HTTPException
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import Session
from sqlmodel import SQLModel
from starlette import status

import mock_AI_chatbot
import nomicAI_GPT4All_caller
import openAI_GPT_API_caller
import settings
from config_loader import load_config

from message_datamodel import Message
from mock_datastore import fake_users_db
from oauth2_token import oauth2_scheme, Token, create_access_token
from user import authenticate_user


#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

DEFAULT_CONVERSATION_MESSAGES_LIMIT = 10
DEFAULT_SYSTEM_MESSAGE = "Hello, how do You do?" # FIXME: need to better context init system message


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


if __name__ == '__main__':
    uvicorn.run(app, log_config=settings.LOGGING_CONFIG)


@app.on_event("startup")
def on_startup():
    logger.info("Startup...")
    create_db_and_tables()


# somke test endpoints

@app.get("/")
def root():
    logger.info('GET root')
    return {"message": "Hello World"}


@app.get("/hello/{name}")
def say_hello(name: str):
    logger.info('GET hello with name: ' + name)
    return {"message": f"Hello {name}"}


# from this business endpoints

@app.post("/message")
def create_message(message: Message, session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]) -> Message:
    logger.info("Create message...")

    # check role of last message of current user
    previous_user_message = session.query(Message) \
        .order_by(desc(Message.create_time)) \
        .where(Message.username == message.username) \
        .limit(1) \
        .all()
    if previous_user_message is not None and len(previous_user_message) > 0 \
            and previous_user_message[0].role != openAI_GPT_API_caller.USER_ROLE:
        # execute if role of last message is not user role only: provide order system-user-assistant-user-assistant

        # assume, that empty role is user and system role included in message sent from client always
        if message.role is None:
            message.role = openAI_GPT_API_caller.USER_ROLE
        message.create_time = datetime.now()
        session.add(message)
        session.commit()
        session.refresh(message)

        # FIXME: from this logic OpenAI GPT API specific - refactor to there!
        # TODO: config based limiting (message / word / token quantity) - missing details (example cutting logic)
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

        # TODO: config based chat API using
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
    else:
        raise HTTPException(status_code=400, detail="Last message was user message...")


@app.get("/messages")
def read_messages(
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
def read_message(message_id: int, session: SessionDep) -> Message:
    logger.info("Get message...")
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    return message


@app.delete("/message/{message_id}")
def delete_message(message_id: int, session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]):
    logger.info("Delete message...")
    message = session.get(Message, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    session.delete(message)
    session.commit()
    return {"ok": True}


@app.post("/register")
def register_user(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    # FIXME: save user data to DB
    return login_for_access_token(form_data)


@app.post("/login")
def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")


@app.get("/logout")
def logout():
    # TODO: logout logic (cleanup, invalidate token, ...etc.)
    return {"logged out": True}
