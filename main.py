from typing import Annotated

from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse

from auth.auth import authenticate_user, create_access_token, get_current_user, oauth2_scheme
from config import ACCESS_TOKEN_EXPIRE_MINUTES
from auth.db import connect_to_db, close_all_connections
from auth.models import Token, User

app = FastAPI()


@app.post("/login_or_token")
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
    response.set_cookie(key="access_token", value=access_token, secure=True, httponly=True)
    return response

@app.post("/logout")
async def logout():
    response = JSONResponse(status_code=200, content={"message": "Logged out successfully"})
    response.delete_cookie(key="access_token")
    return response

@app.on_event("startup")
async def startup():
    await connect_to_db()

@app.on_event("shutdown")
async def shutdown():
    await close_all_connections()


@app.get("/users/whoami")
async def whoami(
        current_user: Annotated[User, Depends(get_current_user)],
):
    return current_user


@app.get("/items/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}
