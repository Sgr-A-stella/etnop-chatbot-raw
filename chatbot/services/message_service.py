from datetime import datetime
from schemas import MessageResponse

class MessageService:
    def __init__(self):
        self.messages = []
        self.next_id = 1

    def get_messages(self, limit: int = 10) -> list[MessageResponse]:
        return self.messages[-limit:]

    def add_user_message(self, user: str, content: str) -> MessageResponse:
        msg = MessageResponse(
            id=self.next_id,
            user=user,
            content=content,
            role="user",
            timestamp=datetime.now()
        )
        self.messages.append(msg)
        self.next_id += 1
        return msg

    def add_bot_message(self, content: str) -> MessageResponse:
        msg = MessageResponse(
            id=self.next_id,
            user="bot",
            content=content,
            role="bot",
            timestamp=datetime.now()
        )
        self.messages.append(msg)
        self.next_id += 1
        return msg
