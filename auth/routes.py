from typing import Annotated

from datetime import timedelta

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse

from auth.auth import authenticate_user, create_access_token, get_current_user, get_password_hash
from config import ACCESS_TOKEN_EXPIRE_MINUTES
from auth.db import db
from auth.models import User


router = APIRouter()

@router.post("/register")
async def register(username: str, password: str, email: str, firstname: str | None = None, lastname: str | None = None ):
    query = "INSERT INTO users (username, hashed_password, email, first_name, last_name) VALUES (:username, :hashed_password, :email, :first_name, :last_name)"
    values = {
        "username": username,
        "hashed_password": get_password_hash(password),
        "email": email,
        "first_name": firstname,
        "last_name": lastname,
    }
    await db.execute(query=query, values=values)
    return {"status": "ok"}


@router.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    response = JSONResponse(status_code=200, content={"message": "Logged in successfully"})
    response.set_cookie(key="access_token",
                        value=access_token,
                        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                        secure=True,
                        httponly=True)
    return response

@router.post("/logout")
async def logout():
    response = JSONResponse(status_code=200, content={"message": "Logged out successfully"})
    response.delete_cookie(key="access_token")
    return response


@router.get("/users/whoami")
async def whoami(
        current_user: Annotated[User, Depends(get_current_user)],
):
    to_print = {k: v for k, v in dict(current_user).items() if k != 'hashed_password'}
    return to_print