from flask import session

class UserSession:
    def create(self, user_id: int, name: str, private_key: str):
        session["user_id"] = user_id
        session["name"] = name
        session["private_key"] = private_key

    @property
    def read(self) -> tuple[int, str, str]:
        return session.get("user_id"), session.get("name"), session.get("private_key")

user_session = UserSession()