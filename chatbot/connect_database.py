"""Database connection module

Both URL based and details based DB engine creation.
"""
import logging

from sqlalchemy import create_engine
from sqlmodel import SQLModel

from config_loader import load_config


logger = logging.getLogger('uvicorn.error')

URL_KEY = "url"
DEFAULT_PG_URL = "postgresql+psycopg2://postgres:postgres@localhost:5432/chatbot"


def create_db_and_tables(engine):
    logger.info("DB connection:")
    logger.info(engine.url)
    logger.info("Create all missed (!) DB objects by engine and SQLModel metadata...")
    SQLModel.metadata.create_all(engine)


def create_engine_by_url():
    config = load_config(section="DB-url")
    url = config[URL_KEY]
    engine = create_engine(DEFAULT_PG_URL if url is None else url)
    logger.info("Engine database: " + engine.url.database)
    return engine


def create_engine_by_details():
    config = load_config(section="postgresql")
    url = create_url_from_config(**config)
    engine = create_engine(DEFAULT_PG_URL if url is None else url)
    logger.info("Engine database: " + engine.url.database)
    return engine


def create_url_from_config(**config):
    url = "postgresql+psycopg2://" + config['user'] + ":" + config['password'] + \
          "@" + config['host'] + ":" + config['port'] + "/" + config['database']
    return url
