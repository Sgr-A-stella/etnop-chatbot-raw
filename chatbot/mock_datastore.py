"""Mock datastore module

This Python file implements mock datastore class for GET messages and POST message(s) REST endpoints.
FIXME: logic for users only, missing logic for messages
"""

fake_messages_db = {
    "johndoe": {
        "id": 1,
        "username": "johndoe",
        "role": "system",
        "message_text": "Hello. How do You do?",
        "create_time": "2024.01.25T22:00:00",
    }
}


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "disabled": False,
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
    }
}
