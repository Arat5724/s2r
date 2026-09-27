"""Request dependency used by catalog routes."""

from fastapi import Request

from .database import Database


def get_db(request: Request) -> Database:
    return request.app.state.db

