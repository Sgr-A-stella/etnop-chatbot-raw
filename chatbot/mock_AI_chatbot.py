"""Mock AI chatbot module

This Python file implements mock AI APIs for POST message(s) REST endpoint.

"""
from typing import Any

from pydantic import typing


default_model_name = "mockChatbot"


def call_GPT_API_chat_completion_with_message_response(
        system_message: str, user_assistant_messages: list[str], model_name=default_model_name):
    return "Hello. I'm an mock OpenAI GPT chatbot. I'm sorry, but that's all I know..."


def generate_response(message: str, model: typing.Union[Any, None]):
    return "Hello. I'm an mock NomicAI GPT4All chatbot. I'm sorry, but that's all I know..."
