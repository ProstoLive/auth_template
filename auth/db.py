from databases import Database

from config import DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME
from auth.models import UserInDB

db = Database(f"postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")


async def connect_to_db():
    await db.connect()


async def close_all_connections():
    await db.disconnect()


#Select user with username from database
async def get_user(username: str):
    query = "SELECT * FROM users WHERE username = :username"
    result = await db.fetch_one(query, {"username": username})
    if result:
        return UserInDB(**result)