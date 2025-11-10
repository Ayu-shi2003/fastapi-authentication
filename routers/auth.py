from datetime import datetime, timedelta
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from starlette import status
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from jose import jwt,JWTError

router = APIRouter(
    prefix ='/auth',
    tags=['auth']
)
SECRET_KEY = 'c426cf1468c1d273ad8fd3f9f2bddd9197cd213b4244e7a71adf762b593dc7f9'
AlGORITHM='HS256'

bcrypt_context=CryptContext(schemes=['bcrypt'],deprecated='auto')

class CreateUserRequest(BaseModel):
    username:str
    email:str
    first_name:str
    last_name:str
    password:str
    role:str

class Token(BaseModel):
    access_token : str
    token_type:str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session,Depends(get_db)]
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")


def authencticate_user(username:str,password:str,db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password,user.hashed_password):
        return False
    return user


def create_access_token(username:str,user_id:int,role:str,
                        expires_delta:timedelta):
    encode = {'sub':username,'id':user_id,'role':role}
    expire = datetime.utcnow()+expires_delta
    encode.update({'exp':expire})
    return jwt.encode(encode,SECRET_KEY,algorithm=AlGORITHM)

async def get_current_user(token:Annotated[str,Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY,algorithms=[AlGORITHM])
        username: str = payload.get('sub')
        user_id= payload.get('id')
        user_role:str=payload.get('role')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user')
        return {'username':username,'id':user_id,'user_role':user_role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user.')


@router.post("/",status_code = status.HTTP_201_CREATED)
async def create_user(create_user_request:CreateUserRequest,db:db_dependency):
    create_user_model = Users(
        email=create_user_request.email,
        username=create_user_request.username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        role=create_user_request.role,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        is_active=True
    )
    db.add(create_user_model)
    db.commit()

@router.post("/token",response_model=Token)
async def login_for_access_token(form_data:Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):
    user = authencticate_user(form_data.username,form_data.password,db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user')
    token = create_access_token(user.username,user.id,user.role,
                                timedelta(minutes=20))
    return {'access_token':token,'token_type':'bearer'}