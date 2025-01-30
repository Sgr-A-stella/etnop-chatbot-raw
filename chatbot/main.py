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

FIXME: user persistence logic for mock_database only, message persistence logic for ORM class / RDBMS only
FIXME: user persistence logic for ORM class / RDBMS and message persistence logic for mock_database missing
"""

from datetime import datetime
from typing import Annotated

import uvicorn
import logging

from fastapi import FastAPI, HTTPException
from fastapi.openapi.models import Response
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordRequestForm

import config_loader
from oauth2_register_rquest_form import OAuth2RegisterRequestForm

from sqlalchemy import desc
from sqlalchemy.orm import Session
from starlette import status

import mock_AI_chatbot
import nomicAI_GPT4All_caller
import openAI_GPT_API_caller
import settings

from connect_database import create_db_and_tables, create_engine_by_url, create_engine_by_details
from datamodels import Message, User
from mock_datastore import fake_users_db
from oauth2_token import oauth2_scheme, Token, create_access_token
from user import authenticate_user, create_new_user


DEFAULT_CONVERSATION_LIMIT_TYPE = "MESSAGE"
DEFAULT_CONVERSATION_LIMIT = 10
DEFAULT_SYSTEM_MESSAGE = "Hello, how do You do?"  # FIXME: need to better context init system message
DEFAULT_SYSTEM_MESSAGE_ROLE = "system"
DEFAULT_USER_MESSAGE_ROLE = "user"
DEFAULT_ASSISTANT_MESSAGE_ROLE = "assistant"

chatbot_config = config_loader.load_config()

CONVERSATION_LIMIT_TYPE_KEY = "conversation.limit.type"
conversation_limit_type = chatbot_config[CONVERSATION_LIMIT_TYPE_KEY] \
    if chatbot_config[CONVERSATION_LIMIT_TYPE_KEY] is not None \
    else DEFAULT_CONVERSATION_LIMIT_TYPE
CONVERSATION_LIMIT_KEY = "conversation.limit.count"
conversation_messages_limit = int(chatbot_config[CONVERSATION_LIMIT_KEY]) \
    if chatbot_config[CONVERSATION_LIMIT_KEY] is not None \
    else DEFAULT_CONVERSATION_LIMIT
USER_MESSAGE_ROLE_KEY = "user.message.role"
user_message_role = chatbot_config[USER_MESSAGE_ROLE_KEY] if chatbot_config[USER_MESSAGE_ROLE_KEY] is not None \
    else DEFAULT_USER_MESSAGE_ROLE
ASSISTANT_MESSAGE_ROLE_KEY = "assistant.message.role"
assistant_message_role = chatbot_config[ASSISTANT_MESSAGE_ROLE_KEY] if chatbot_config[ASSISTANT_MESSAGE_ROLE_KEY] is not None \
    else DEFAULT_ASSISTANT_MESSAGE_ROLE
SYSTEM_MESSAGE_ROLE_KEY = "system.message.role"
system_message_role = chatbot_config[SYSTEM_MESSAGE_ROLE_KEY] if chatbot_config[SYSTEM_MESSAGE_ROLE_KEY] is not None \
    else DEFAULT_SYSTEM_MESSAGE_ROLE
SYSTEM_MESSAGE_KEY = "system.message.content"
system_message = chatbot_config[SYSTEM_MESSAGE_KEY] if chatbot_config[SYSTEM_MESSAGE_KEY] is not None \
    else DEFAULT_SYSTEM_MESSAGE

rate_llimit = False


app = FastAPI(title='chatbot')
logger = logging.getLogger('uvicorn.error')
db_engine = create_engine_by_url()
#db_engine = create_engine_by_details()  # for details based DB-engine creating


def get_session():
    logger.info("Engine database: " + db_engine.url.database)
    with Session(db_engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]


if __name__ == '__main__':
    uvicorn.run(app, log_config=settings.LOGGING_CONFIG)

def load_url_from_config(**config):
    url = "postgresql+psycopg2://" + config['user'] + ":" + config['password'] + \
          "@" + config['host'] + ":" + config['port'] + "/" + config['database']
    return url

@app.on_event("startup")
def on_startup():
    logger.info("Startup...")
    create_db_and_tables(db_engine)


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
    if previous_user_message is not None and (len(previous_user_message) == 0 or (len(previous_user_message) > 0 \
            and previous_user_message[0].role != user_message_role)):
        # execute if role of last message is not user role only: provide order system-user-assistant-user-assistant

        # assume, that empty role is user and system role included in message sent from client always
        if message.role is None:
            message.role = user_message_role
        message.create_time = datetime.now()
        session.add(message)
        session.commit()
        session.refresh(message)

        # TODO: config based limiting (MESSAGE / WORD / TOKEN quantity)
        if conversation_limit_type != "MESSAGE":
            logger.warning("MESSAGE based limiting implemented only...")

        messages = session.query(Message)\
            .order_by(desc(Message.create_time))\
            .where(Message.username == message.username and Message.role != system_message_role)\
            .limit(conversation_messages_limit)\
            .all()
        logger.info(f"Messages count: {len(messages)}")
        conversation_messages = [msg.message_text for msg in messages]

        # NOTE: what if last system message after first conversation message...? (prefix of conversation is out of context!)
        sys_msg = session.query(Message) \
            .order_by(desc(Message.create_time)) \
            .where(Message.username == message.username and Message.role != system_message_role) \
            .limit(1) \
            .all()
        logger.info(f"System message count: {len(sys_msg)}")
        system_message = DEFAULT_SYSTEM_MESSAGE if sys_msg is None else sys_msg[0].message_text

        # TODO: design pattern (DI, Strategy, ...etc.) based chat API using
        if chatbot_config["chatbot.type"] is None or chatbot_config["chatbot.type"] == "MOCK":
            if chatbot_config["chatbot.type"] is None:
                logger.warning("Empty chatbot type configuration (using mock)")
            response_message_text = mock_AI_chatbot.generate_response(message.message_text, None)
        elif chatbot_config["chatbot.type"] == "CHATGPT":
            response_message_text = openAI_GPT_API_caller.call_GPT_API_chat_completion_with_message_response(
                system_message, conversation_messages)
        elif chatbot_config["chatbot.type"] == "GPT4ALL":
            response_message_text = nomicAI_GPT4All_caller.generate_response(message.message_text, None)
        elif chatbot_config["chatbot.type"] == "DEEPSEEK":
            logger.warning("DEEPSEEK chatbot is not implemented yet...")
        else:
            logger.error("Invalid chatbot type configuration (using mock): " + chatbot_config["chatbot.type"])
            response_message_text = mock_AI_chatbot.generate_response(message.message_text, None)

        response_message = Message()
        response_message.message_text = response_message_text
        response_message.username = message.username
        response_message.role = assistant_message_role
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
        form_data: Annotated[OAuth2RegisterRequestForm, Depends()],
) -> Token:
    user = create_new_user(fake_users_db, form_data.username, form_data.password, form_data.email, form_data.fullname)
    return create_token(user)


@app.post("/login")
def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    return create_token(user)


def create_token(user):
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")


@app.get("/logout")
def logout(#response: Response,
           session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        # TODO: logout logic (cleanup, invalidate token, ...etc.)
        #response.delete_cookie(key="access_token")
        #response.delete_cookie(key="refresh_token")
        return {"message": "Logged out successfully"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
