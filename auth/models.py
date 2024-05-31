from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


#Basic pydantic model of user

class User(BaseModel):
    username: str
    email: str
    first_name: str | None = None
    last_name: str | None = None


#Model of how user will be in db. Inherits from User
class UserInDB(User):
    hashed_password: str