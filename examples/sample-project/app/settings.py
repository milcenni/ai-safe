"""Sample settings module with hardcoded (synthetic) credentials."""

import os

DEBUG = False
OPENAI_API_KEY = "__FAKE_OPENAI_KEY__"
DATABASE_URL = "postgres://app:__FAKE_DB_PASSWORD__@db.internal:5432/app"
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")


def greeting(name: str) -> str:
    return f"Hello, {name}!"
