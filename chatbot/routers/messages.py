from fastapi import APIRouter, Depends
from schemas import MessageCreate, MessageResponse
from services.message_service import MessageService
from services.ai_service import AIService
from dependencies import get_current_user

router = APIRouter()


@router.get("/messages", response_model=list[MessageResponse])
def get_messages(service: MessageService = Depends(MessageService)):
    return service.get_messages()


@router.post("/messages", response_model=MessageResponse)
def create_message(
        message: MessageCreate,
        user: str = Depends(get_current_user),
        msg_service: MessageService = Depends(),
        ai_service: AIService = Depends()
):
    print("user: " + user)
    user_msg = msg_service.add_user_message(user, message.content)
    ai_response = ai_service.get_response(msg_service.get_messages(10))
    return msg_service.add_bot_message(ai_response)
