from fastapi import FastAPI

from app.database import lifespan

app: FastAPI = FastAPI(lifespan=lifespan)

