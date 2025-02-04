from fastapi import FastAPI
from routers.messages import router as messages_router

app = FastAPI()
app.include_router(messages_router)

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}
