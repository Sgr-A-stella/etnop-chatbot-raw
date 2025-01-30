"""Configuration (ex.: database connection) loader module
"""
import logging

from configparser import ConfigParser


logger = logging.getLogger('uvicorn.error')


def load_config(filename='configuration.ini', section='chatbot'):
    """ Load configuration

    :param filename: name of config file
    :param section: name of config section
    :return: given section configuration values in dictionary
    """
    parser = ConfigParser()
    parser.read(filename)

    # get section, default to DB-url
    config = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            config[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    logger.info("Loaded config:")
    logger.info(config)

    return config
