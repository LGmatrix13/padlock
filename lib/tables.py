
import sqlite3
from flask import g

DATABASE = "db.sqlite3"

def connect() -> tuple[sqlite3.Connection, sqlite3.Cursor]:
    conn = sqlite3.connect(DATABASE)
    return conn, conn.cursor()

def close(conn: sqlite3.Connection, cursor: sqlite3.Cursor):
    conn.close()
    cursor.close()

class Texts:
    def __init__(self) -> None:
        conn, cursor = connect()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS texts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_user_id INTEGER NOT NULL,
                sender_user_id INTEGER NOT NULL,
                sender TEXT NOT NULL,
                context TEXT NOT NULL,
                nonce BYTES NOT NULL,
                session_key BYTES NOT NULL,
                ciphertext BYTES NOT NULL,
                signature BYTES NOT NULL,
                FOREIGN KEY (sender_user_id) REFERENCES users(id)
                FOREIGN KEY (recipient_user_id) REFERENCES users(id)
            )
        ''')  
        conn.commit()
    def create(self, recipient_user_id: int, sender_user_id: int, sender: str, context: str, nonce: bytes, session_key: bytes, ciphertext: bytes, signature: bytes):
        conn, cursor = connect()
        data = (recipient_user_id, sender_user_id, sender, context, nonce, session_key, ciphertext, signature)
        cursor.execute('''
            INSERT INTO texts
            (recipient_user_id, sender_user_id, sender, context, nonce, session_key, ciphertext, signature)
            values(?, ?, ?, ?, ?, ?, ?, ?)
        ''', data)  
        conn.commit() 
    def read(self, user_id) -> list[tuple[int, int, int, str, str, bytes, bytes, bytes, bytes]]:
        _, cursor = connect()
        cursor.execute('''
            SELECT * FROM texts
            WHERE recipient_user_id = ?
            ORDER BY id DESC
        ''', [user_id])
        rs = cursor.fetchall()
        return rs
        
texts = Texts()

class Users:
    def __init__(self) -> None:
        conn, cursor = connect()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL
            )
        ''')  
        conn.commit()  
    def read_all(self) -> list[int, str]:
        conn, cursor = connect()
        cursor.execute('''
            SELECT id, name FROM users
        ''')
        conn.commit()  
        rs = cursor.fetchall()
        return rs
    def read(self, user_id: int) -> tuple[int, str, str]:
        _, cursor = connect()
        cursor.execute('''
            SELECT * FROM users
            WHERE id = ?
        ''', [user_id])
        rs = cursor.fetchall()
        return rs[0]
    def read_from_public_key(self, public_key: str) -> tuple[int, str, str]:
        _, cursor = connect()
        cursor.execute('''
            SELECT * FROM users
            WHERE public_key = ?
        ''', [public_key])
        rs = cursor.fetchall()
        return rs[0]
    def create(self, name: str, key: str) -> tuple[int, str, str]:
        conn, cursor = connect()
        data = (name, key)
        cursor.execute('''
            INSERT INTO users
            (name, public_key)
            values(?, ?)
            RETURNING *
        ''', data)
        rs = cursor.fetchall()
        conn.commit()  
        return rs[0]
    def delete(self, user_id: int) -> tuple[int, str, str]:
        conn, cursor = connect()
        cursor.execute('''
            DELETE FROM users
            WHERE id = ?
            RETURNING *
        ''', [user_id])
        rs = cursor.fetchall()
        conn.commit()
        return rs[0]

users = Users()