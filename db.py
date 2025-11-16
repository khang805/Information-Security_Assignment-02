import mysql.connector
from mysql.connector import pooling
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class DBConfig:
    host: str
    port: int
    name: str
    user: str
    password: str

class DB:
    def __init__(self, cfg: DBConfig):
        self.pool = pooling.MySQLConnectionPool(
            pool_name="securechat_pool",
            pool_size=5,
            host=cfg.host, port=cfg.port, database=cfg.name,
            user=cfg.user, password=cfg.password
        )

    def register_user(self, email: str, username: str, salt: bytes, pwd_hash_hex: str) -> bool:
        try:
            conn = self.pool.get_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
                (email, username, salt, pwd_hash_hex)
            )
            conn.commit()
            return True
        except mysql.connector.Error:
            return False
        finally:
            try:
                cur.close(); conn.close()
            except Exception:
                pass

    def get_user(self, username: Optional[str], email: Optional[str]) -> Optional[Tuple[str, bytes, str]]:
        conn = self.pool.get_connection()
        cur = conn.cursor()
        try:
            if username:
                cur.execute("SELECT username, salt, pwd_hash FROM users WHERE username=%s", (username,))
            else:
                cur.execute("SELECT username, salt, pwd_hash FROM users WHERE email=%s", (email,))
            row = cur.fetchone()
            if not row: return None
            return (row[0], row[1], row[2])
        finally:
            cur.close(); conn.close()
