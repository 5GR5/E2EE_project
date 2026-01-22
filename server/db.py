import os
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

load_dotenv()

# loads the database URL - using SQLite for simplicity (perfect for school projects!)
# Database is in parent directory
import pathlib
DB_PATH = pathlib.Path(__file__).parent.parent / "securemsg.db"
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# makes sure every request gets its own session
async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session
