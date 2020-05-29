import json
from datetime import datetime

class User:
    def create_user(id: int, username: str, pseudo: str, created_at: datetime, email: str) -> str:
        return json.dumps({
            "id": id,
            "username": username,
            "pseudo": pseudo
            "created_at": created_at
            "email": email #PROPRIETAIRE
        })


class Video:
    def create_video(id: int, source: str, created_at: datetime, views: int, enabled: bool, user: str, format: dict):
        return json.dumps({
            "id": id,
            "source": source,
            "created_at": created_at
            "views": views
            "enabled": enabled
            "user": user
            "format": format
        })

class Token:
    def create_token(token: str, user: str):
        return json.dumps({
            "token": token,
            "user": user,
        })

class Comment:
    def create_comment(id: int, body: str, user: str):
        return json.dumps({
            "id": id,
            "body": body,
            "user": user
        })

class Error:
    def create_error(message, code, data):
        return json.dumps({
            "message": message,
            "code": code,
            "data": data
        })
