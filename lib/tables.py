import sqlite3

conn = sqlite3.connect('db.sqlite3', check_same_thread=False)
cursor = conn.cursor()

class Texts:
    def __init__(self) -> None:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS texts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_user_id INTEGER NOT NULL,
                sender_user_id INTEGER NOT NULL,
                sender TEXT NOT NULL,
                context TEXT NOT NULL,
                nonce TEXT NOT NULL,
                session_key TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                signature TEXT NOT NULL,
                FOREIGN KEY (sender_user_id) REFERENCES users(id)
                FOREIGN KEY (recipient_user_id) REFERENCES users(id)
            )
        ''')  
        conn.commit()
        print("Created texts table")  
    def create(self, recipient_user_id: int, sender_user_id: int, sender: str, context: str, nonce: str, session_key: str, ciphertext: str, signature: str):
        data = (recipient_user_id, sender_user_id, sender, context, nonce, session_key, ciphertext, signature)
        cursor.execute('''
            INSERT INTO texts
            (recipient_user_id, sender_user_id, sender, context, nonce, session_key, ciphertext, signature)
            values(?, ?, ?, ?, ?, ?, ?, ?)
        ''', data)  
        conn.commit()  
    def read(self, user_id) -> list[tuple[int, int, int, str, str, str, str, str]]:
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL
            )
        ''')  
        conn.commit()  
        print("Created users table")
    def read_all(self) -> list[int, str]:
        cursor.execute('''
            SELECT id, name FROM users
        ''')
        rs = cursor.fetchall()
        return rs
    def read(self, user_id: int) -> tuple[int, str, str]:
        cursor.execute('''
            SELECT * FROM users
            WHERE id = ?
        ''', [user_id])
        rs = cursor.fetchall()
        return rs[0]
    def read_from_public_key(self, public_key: str) -> tuple[int, str, str]:
        cursor.execute('''
            SELECT * FROM users
            WHERE public_key = ?
        ''', [public_key])
        rs = cursor.fetchall()
        return rs[0]
    def create(self, name: str, key: str):
        data = (name, key)
        print(data)
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
        cursor.execute('''
            DELETE FROM users
            WHERE id = ?
            RETURNING *
        ''', [user_id])
        rs = cursor.fetchall()
        conn.commit()
        return rs[0]

users = Users()