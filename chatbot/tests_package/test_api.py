from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_read_empty_messages():
    response = client.get("/messages")
    assert response.status_code == 200
    assert response.json() == []


def test_post_message_forbidden():
    response = client.post("/messages", json={"content": "Hello, nincs API kulcsom..."})
    assert response.status_code == 403


def test_post_message_unauthorized():
    response = client.post("/messages",
                           json={"content": "Hello, nem érvényes az API kulcsom..."},
                           headers={"X-API-Key": "invalid_api_key"}
                           )
    assert response.status_code == 401


def test_post_message_authorized():
    response = client.post(
        "/messages",
        json={"content": "Teszt üzenet"},
        headers={"X-API-Key": "test_api_key"}
    )
    assert response.status_code == 200
    assert "Válasz erre" in response.json()["content"]
