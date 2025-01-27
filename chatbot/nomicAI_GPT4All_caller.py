"""Nomic-AI GPT4All (based LLaMa architecture and open-source) API integration module

This open-source model requires download (depending on model name) 2-8 GB LLM file and
running of it requires 4-16 GB RAM with various (from Apache to MIT) licenses.
(Default model requires smallest resources and MIT license.)
"""

from gpt4all import GPT4All

from pydantic import typing


default_model_name = "hi-3-mini-4k-instruct.Q4_0.gguf"
accepted_model_names = ["hi-3-mini-4k-instruct.Q4_0.gguf", "Meta-Llama-3-8B-Instruct.Q4_0.gguf",
                        "gpt4all-13b-snoozy-q4_0.gguf"]
# exists more model names, for current model names and aliases see:
# https://docs.gpt4all.io/gpt4all_python/home.html#load-llm


def get_model(model_name=default_model_name):
    """get LLM model

    If not available then download and run, see above!

    :param model_name: optinal parameter for override default model name
    :return: model of running LLM
    """
    model = GPT4All(model_name)
    return model


def create_session(model: typing.Union[GPT4All, None]):
    """create session for conversation

    :param model:
    :return: model with started session
    """
    new_model = get_model() if model is None else model
    new_model.chat_session(model)
    return new_model


def generate_response(message: str, model: typing.Union[GPT4All, None]):
    """generate response message for user message

    :param message: user message
    :param model:
    :return: response
    """
    new_model = get_model() if model is None else model
    if new_model.current_chat_session is None:
        return model.generate(message)
    else:
        with model.current_chat_session():
            return model.generate(message)


def close_model(model: typing.Union[GPT4All, None]):
    """close model instance

    :param model:
    """
    assert isinstance(model, GPT4All), "`model` should be a GPT4All"
    model.close()
