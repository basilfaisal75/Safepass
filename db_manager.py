import sqlite3
import logging
import bcrypt
from encryption_utils import encrypt_password, decrypt_password

# set up logging
logging.basicConfig(
    level=logging.INFO,
    filename="safepass.log",
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class DatabaseManager:
    def __init__(self):
        # open th3 SQLite database file
        self.conn = sqlite3.connect('safepass_app.db')
        # ensure the needed tables exist
        self.create_tables()

    def create_tables(self):
        # create users and passwords tables if they don't already exist
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password BLOB NOT NULL
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    password TEXT NOT NULL,
                    strength TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
        logging.info("Database tables ready.")  # Log that setup is complete

    def register_user(self, username: str, password: str) -> bool:

        #Try to create a new user. returns true on success, false if the username is taken

        try:
            # hash the plaintext password with bcrypt
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with self.conn:
                self.conn.execute(
                    "INSERT INTO users(username,password) VALUES (?,?)",
                    (username, hashed)
                )
            logging.info("Registered new user: %s", username)
            return True
        except sqlite3.IntegrityError:
            # unique constraint failed: username already exists
            logging.warning("Registration failed, username exists: %s", username)
            return False

    def login_user(self, username: str, password: str):

        #verify a login attempt
        #returns the user_id on success, or none if credentials dont match

        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, password FROM users WHERE username=?",
            (username,)
        )
        row = cur.fetchone()
        if row:
            user_id, hashed = row
            # ensure hashed is in bytes for bcrypt
            if isinstance(hashed, str):
                hashed = hashed.encode()
            # check the provided password against our stored hash
            if bcrypt.checkpw(password.encode(), hashed):
                logging.info("Login successful for user_id %s", user_id)
                return user_id

        # if we get here, authentication failed
        logging.warning("Login failed for username: %s", username)
        return None

    def save_password(self, user_id: int, plain_pw: str, strength: str, master_pw: str):

        # encrypt the users new password using their login password as the key
        enc = encrypt_password(plain_pw, master_pw)

        with self.conn:
            self.conn.execute(
                "INSERT INTO passwords(user_id,password,strength) VALUES(?,?,?)",
                (user_id, enc, strength)
            )
        logging.info("Saved encrypted password for user %s", user_id)

    def get_passwords(self, user_id: int, master_pw: str):

        # Retrieve and decrypt all passwords for the given user id.


        cur = self.conn.cursor()
        cur.execute(
            "SELECT password, strength FROM passwords WHERE user_id=?",
            (user_id,)
        )

        out = []
        for enc_pw, strength in cur.fetchall():
            try:
                # attempt to decrypt each stored blob
                dec_pw = decrypt_password(enc_pw, master_pw)
            except Exception:
                # if decryption fails (wrong master_pw, corrupted data, )
                dec_pw = "[DECRYPTION ERROR]"
                logging.error("Failed to decrypt password for user %s", user_id)

            out.append((dec_pw, strength))

        logging.info("Retrieved %d passwords for user %s", len(out), user_id)
        return out
