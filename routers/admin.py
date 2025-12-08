from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from models import Users, Todos
from database import SessionLocal
from typing import Annotated
from .auth import get_current_user

router = APIRouter(
    prefix="/admin",
    tags=["admin"]
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get("/users")
async def get_all_users(user: user_dependency, db: db_dependency):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access this")
    return db.query(Users).all()


@router.get("/todos")
async def get_all_todos(user: user_dependency, db: db_dependency):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can access this")
    return db.query(Todos).all()

