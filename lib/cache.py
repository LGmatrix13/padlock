from flask import session

class Cache:
    def __init__(self, namespace: str) -> None:
        self.namespace = namespace
    def read(self, key):
        return session.get(f"cache_{self.namespace}_{key}")
    def create(self, key, value):
        session[f"cache_{self.namespace}_{key}"] = value