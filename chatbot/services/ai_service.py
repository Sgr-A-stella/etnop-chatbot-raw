class AIService:
    def get_response(self, messages: list) -> str:
        if not messages:
            return "Üdvözöllek! Hogyan segíthetek?"
        return f"Válasz erre: {messages[-1].content}"
