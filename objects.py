from datetime import datetime

class Retour:
    def create_user(id: int, username: str, pseudo: str, created_at: datetime, email: str) -> str:
        return {
            'id': id,
            'username': username,
            'pseudo': pseudo,
            'created_at': created_at,
            'email': email #PROPRIETAIRE
        }

    def create_video(id: int, source: str, created_at: datetime, views: int, enabled: bool, user: str, format: dict):
        return {
            'id': id,
            'source': source,
            'created_at': created_at,
            'views': views,
            'enabled': enabled,
            'user': user,
            'format': format
        }

    def create_token(token: str, user: str):
        return {
            'token': token,
            'user': user
        }

    def create_comment(id: int, body: str, user: str):
        return {
            'id': id,
            'body': body,
            'user': user
        }

    def create_error(message, code, data):
        return {
            'message': message,
            'code': code,
            'data': data
        }
