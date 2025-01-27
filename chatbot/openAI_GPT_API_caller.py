"""OpenAI GPT API integration module

Note that OpenAI charges to use the GPT API. (Free credits are sometimes provided to new users,
but who gets credit and how long this deal will last is not transparent.) It costs $0.002 / 1000 tokens,
where 1000 tokens equal about 750 words.
"""

import os

import tiktoken as tiktoken
from openai import OpenAI

from pydantic import typing
import json


OpenAI.api_key = os.environ.get("OPENAI")
default_model_name = "gpt-3.5-turbo"
accepted_model_names = ["gpt-3.5-turbo", "gpt-4o-mini"]
# exists more model names, for current model names and aliases see: https://platform.openai.com/docs/models/overview

SYSTEM_ROLE = "system"
USER_ROLE = "user"
ASSISTANT_ROLE = "assistant"
accepted_role_names = [SYSTEM_ROLE, USER_ROLE, ASSISTANT_ROLE]
'''There are three types of message documented in the Introduction to the Chat documentation:

    'system' messages describe the behavior of the AI assistant. A useful system message for data science use cases is 
            "You are a helpful assistant who understands data science."
    'user' messages describe what you want the AI assistant to say.
    'assistant' messages describe previous responses in the conversation.
'''

class RoledMessage:
    """Message with role for conversation
        (MessageWithRole maybe grammatical correct, but more expressive order and dialogue form)
        The first message should be a system message.
        Additional messages should alternate between the user and the assistant.
    """
    role: str
    content: str


def call_GPT_API_chat_completion_with_raw_response(
        roled_conversation_context: list[RoledMessage],
        model_name: typing.Union[str, None]):
    """call OpenAI GPT version 3.5 API chat completion with model and messages, later is user-GPT conversation context

    :param roled_conversation_context messages with actor role of message, that will well form on this JSON way
    messages=[{"role": "system", "content": 'SPECIFY HOW THE AI ASSISTANT SHOULD BEHAVE'},
              {"role": "user", "content": 'SPECIFY WANT YOU WANT THE AI ASSISTANT TO SAY'}]
    :param model_name: optional parameter for override default model name
    (if value None of it, then default model name apply)
   :return response of GPT
    """
    #roled_conversation_context_json: str = json.dumps(roled_conversation_context)
    client = OpenAI()
    response = client.chat.completions.create(
    #response = openai.ChatCompletion.create(
        model=default_model_name if model_name is None else model_name,
        messages=roled_conversation_context
    )
    return response


def call_GPT_API_chat_completion_with_message_response(
        system_message: str, user_assistant_messages: list[str], model_name=default_model_name):
    """

    :param system_message: message describe the behavior of the AI assistant (take it into required context)
    :param user_assistant_messages: conversation (strictly switched u-a dialogue) history with last, new user message
    :param model_name: optional parameter for override default model name
    (if value None of it, then default model name apply)
    :return:
    """
    assert isinstance(system_message, str), "`system_message` should be a string"
    assert isinstance(user_assistant_messages, list), "`user_assistant_messages` should be a list"

    system_msg = [{"role": "system", "content": system_message}]
    user_assistant_msgs = [
        {"role": "assistant", "content": user_assistant_messages[i]} if i % 2
        else {"role": "user", "content": user_assistant_messages[i]}
        for i in range(len(user_assistant_messages))
    ]

    msgs = system_msg + user_assistant_msgs
    client = OpenAI()
    response = client.chat.completions.create(
    #response = openai.ChatCompletion.create(
        model=model_name,
        messages=msgs
    )

    status_code = response["choices"][0]["finish_reason"]
    assert status_code == "stop", f"The status code was {status_code}."

    return response["choices"][0]["message"]["content"]


def num_tokens_from_string(string: str, encoding_name: str) -> int:
    """Returns the number of tokens in a text string for user message limiting."""
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens
