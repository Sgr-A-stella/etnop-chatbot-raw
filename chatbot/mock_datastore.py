"""Mock datastore module

This Python file implements mock datastore class for GET messages and POST message(s) REST endpoints.
"""

from pydantic.dataclasses import dataclass


@dataclass
class MockDataStoreMessages:
    """Mock datastore class for messages"""


@dataclass
class MockDataStoreUsers:
    """Mock datastore for users"""


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}