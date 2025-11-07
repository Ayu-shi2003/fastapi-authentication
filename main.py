from typing import Annotated
from fastapi import FastAPI,Depends,HTTPException,Path
from typing import Annotated
from fastapi import Depends
from sqlalchemy.orm import Session  
import models
from database import engine,SessionLocal
from routers import auth,todos

app = FastAPI()

models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(todos.router)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]