from datetime import datetime, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt

from database import SessionLocal
from models import Users

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# SECRET and ALGO
SECRET_KEY = "61d7a63f50f5d57db36353f3c132f373f05eb11f18ac4ed9aeb5f800294af6b5"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


# Pydantic Schemas
class CreateUserRequest(BaseModel):
    username: str
    email: str
    first_name: str
    last_name: str
    password: str
    role: str
    phone_number:str


class Token(BaseModel):
    access_token: str
    token_type: str


# DB dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


# Authenticate user
def authenticate_user(username: str, password: str, db: Session):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return None
    if not pwd_context.verify(password, user.hashed_password):
        return None
    return user


# Create JWT access token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Dependency: get current logged-in user
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("id")
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None or username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(Users).filter(Users.id == user_id).first()
    if not user:
        raise credentials_exception
    return {"id": user.id, "username": user.username, "role": user.role}


# Create user endpoint
@router.post("/create", status_code=status.HTTP_201_CREATED)
async def create_user(user_request: CreateUserRequest, db: Session = Depends(get_db)):
    existing_user = db.query(Users).filter(Users.username == user_request.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    user_model = Users(
        username=user_request.username,
        email=user_request.email,
        first_name=user_request.first_name,
        last_name=user_request.last_name,
        role=user_request.role,
        hashed_password=pwd_context.hash(user_request.password),
        is_active=True,
        phone_number=user_request.phone_number
    )
    db.add(user_model)
    db.commit()
    db.refresh(user_model)
    return {"id": user_model.id, "username": user_model.username}


# Login endpoint
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(
        data={"sub": user.username, "id": user.id, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}
