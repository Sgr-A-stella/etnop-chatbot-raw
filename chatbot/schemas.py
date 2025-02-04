from datetime import datetime
from pydantic import BaseModel

class MessageCreate(BaseModel):
    content: str

class MessageResponse(BaseModel):
    id: int
    user: str
    content: str
    role: str
    timestamp: datetime
