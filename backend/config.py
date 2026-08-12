import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL  = os.getenv("DATABASE_URL")
SHARED_SECRET = bytes.fromhex(os.getenv("SHARED_SECRET", ""))