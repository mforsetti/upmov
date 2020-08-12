#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import string
import sqlite3
import time
import base64
import hmac
import hashlib
import uuid
from typing import Tuple
from datetime import datetime
from contextlib import closing
from collections import namedtuple

DATA_DIR = os.path.abspath("/var/lib/upmov")
DB_FILE = DATA_DIR + "/auth.db"

User = namedtuple("User", ["name", "password"])

AuthUser = namedtuple("AuthUser", [
    "uid",
    "uname",
    "password",
    "salt",
    "algorithm",
    "status",
    "created_at",
    "retention_deadline",
    "last_activity"
])

AuthSecret = namedtuple("AuthSecret", [
    "password_hash",
    "algorithm",
    "salt"
])

class AuthDb:
    # the username string must consist only of these characters: alphanumeric, underbar (‘_’), dash (‘-‘), dot (‘.’), or at (‘@’)
    USERNAME_CHARACTERS = string.ascii_letters + string.digits + "_-.@"
    # The password string can consist of any printable characters except for CR or LF.
    PASSWORD_BAD_CHARACTERS = "\r\n"
    # Any illegal characters in either the username or password string will be converted to underbar (‘_’).
    NORMALIZED_CHARACTER = "_"

    MIGRATION_PREFIX = "_migration_rev"

    MIN_USERNAME_LEN = 2
    MAX_USERNAME_LEN = 4096
    MIN_PASSWORD_LEN = 4
    MAX_PASSWORD_LEN = 4096

    MIN_VERSION = 2

    HASH_ALGORITHMS = {
        0: "sha1",
        1: "sha256",
        2: "sha512"
    }

    DEFAULT_HASH_ALGORITHM = 2
    DEFAULT_RETENTION_DEADLINE = 604800

    FLAG_OK = 0x0
    FLAG_RETENTION = 0x1
    FLAG_EXPIRE = 0x2

    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self.user = None
        self.db = None

    def connect(self):
        if not self.db:
            try:
                self.db = sqlite3.connect(self.db_file)
                self.db.row_factory = sqlite3.Row
            except:
                raise RuntimeError("Failed opening authentication database.")

    def ping(self):
        self.connect()
        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("SELECT 1")
        except:
            self.db = None
            self.connect()

    def with_user(self, user: User):
        if not isinstance(user, User):
            raise ValueError("Unexpected type of user, expecting User.")

        current_username = AuthDb.filter_username(user.name)
        current_password = AuthDb.filter_password(user.password)

        self.user = User(name=current_username, password=current_password)
        return self

    def __find_user(self) -> AuthUser:
        auth_user = None
        username = self.user.name

        if not username:
            return None

        # find username, fetch password, status, salt, algorithm, retention_deadline
        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("""SELECT uid, uname, password, salt, algorithm, status, strftime("%s", created_at) AS created_at, retention_deadline, last_activity
                                FROM auth
                                WHERE uname = ?""", (username,))

                while True:
                    temp = cursor.fetchone()
                    if not temp:
                        break

                    if auth_user: # handle multiple user result, injection?
                        return None

                    auth_user = AuthUser(uid               = temp["uid"],
                                        uname              = temp["uname"],
                                        password           = temp["password"],
                                        salt               = temp["salt"],
                                        algorithm          = temp["algorithm"],
                                        status             = temp["status"],
                                        created_at         = int(temp["created_at"]),
                                        retention_deadline = temp["retention_deadline"],
                                        last_activity      = temp["last_activity"])
            return auth_user
        except:
            return None

    def __verify_user(self, auth_user: AuthUser) -> bool:
        password = self.user.password

        if password:
            hash_result = AuthDb.hash_password(password=password, algorithm=auth_user.algorithm, salt=auth_user.salt)
            if hmac.compare_digest(hash_result.password_hash, auth_user.password):
                return True

        return False

    def auth(self, validate: bool = False) -> Tuple[bool, str]:
        """Authenticate a username with given password."""
        self.ping()

        if self.migration_version() < AuthDb.MIN_VERSION:
            return False, "Empty or not updated database."

        auth_user = self.__find_user()
        if not auth_user:
            return False, "User not found."

        # validate password
        if not self.__verify_user(auth_user=auth_user):
            return False, "User not found."

        # until here, we're good. we still need to check status and retention_deadline
        # first, we need to check for retention_deadline, but we will keep status otherwise.
        # but, because it's _namedtuple_, it's immutable, so we won't change it

        status_flag = AuthDb.FLAG_OK
        current_time = int(time.time())

        if not auth_user.retention_deadline == 0:
            if auth_user.last_activity == 0:
                # no last activity, use created_at
                if (auth_user.created_at + auth_user.retention_deadline) < current_time:
                    status_flag = AuthDb.FLAG_EXPIRE
            else:
                if auth_user.last_activity + auth_user.retention_deadline < current_time:
                    if current_time - auth_user.last_activity >= 3 * auth_user.retention_deadline:
                        status_flag = AuthDb.FLAG_EXPIRE
                    else:
                        status_flag = AuthDb.FLAG_RETENTION

        # flag is OK, based on auth_user; but let's update our database.
        update_status = validate

        if not status_flag == auth_user.status:
            update_status = True

        if status_flag == AuthDb.FLAG_OK:
            ret = (True, "OK!")
        else:
            ret = (False, "User invalid or expired.")

        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("BEGIN TRANSACTION")
                cursor.execute("UPDATE auth SET last_activity = ? WHERE uid = ?", (current_time, auth_user.uid))
                if update_status:
                    if validate:
                        cursor.execute("UPDATE auth SET status = ? WHERE uid = ?", (AuthDb.FLAG_OK, auth_user.uid))
                    else:
                        cursor.execute("UPDATE auth SET status = ? WHERE uid = ?", (status_flag, auth_user.uid))
                cursor.execute("COMMIT TRANSACTION")
        except:
            return False, "Database error!"

        return ret

    @staticmethod
    def base64_encode(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).replace(b"=", b"")

    @staticmethod
    def base64_decode(b64_data: bytes) -> bytes:
        return base64.urlsafe_b64decode(b64_data + b"===")

    @staticmethod
    def hash_password(password: bytes, algorithm: int, salt: bytes = None) -> AuthSecret:
        if not salt:
            salt = os.urandom(32)

        if isinstance(salt, str):
            salt = salt.encode("utf-8")

        if isinstance(password, str):
            password = password.encode("utf-8")

        if not algorithm in AuthDb.HASH_ALGORITHMS:
            raise ValueError("Hash algorithm unknown.")

        hmac_obj = hmac.new(key=salt, digestmod=AuthDb.HASH_ALGORITHMS[algorithm])
        hmac_obj.update(password)

        digest = hmac_obj.digest()

        return AuthSecret(password_hash=digest, algorithm=algorithm, salt=salt)

    def register(self) -> Tuple[bool, str]:
        """Register a new username with given password."""
        self.ping()

        if not self.user.name:
            return False, "Bad username."

        if not self.user.password:
            return False, "Bad password."

        if self.migration_version() < AuthDb.MIN_VERSION:
            return False, "Empty or not updated database."

        auth_user = self.__find_user()
        if auth_user:
            return False, "User already exists."

        uid = None
        try:
            with closing(self.db.cursor()) as cursor:
                while not uid:
                    uid = uuid.uuid4().bytes
                    cursor.execute("SELECT uid FROM auth WHERE uid = ?", (uid,))

                    if cursor.fetchone():
                        uid = None
                    else:
                        break
        except:
            return False, "Database error!"

        new_secret = AuthDb.hash_password(password=self.user.password, algorithm=AuthDb.DEFAULT_HASH_ALGORITHM)

        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("INSERT INTO auth (uid, uname, password, salt, algorithm, status) VALUES (?, ?, ?, ?, ?, ?)", (
                    uid,
                    self.user.name,
                    new_secret.password_hash,
                    new_secret.salt,
                    new_secret.algorithm,
                    AuthDb.FLAG_OK
                ))
                self.db.commit()
        except:
            return False, "Database error!"

        return True, "OK!"

    def change_password(self, new_password: str, skip_validation: bool = False) -> Tuple[bool, str]:
        """Change a specified username's password."""
        self.ping()

        if self.migration_version() < AuthDb.MIN_VERSION:
            return False, "Empty or not updated database."

        auth_user = self.__find_user()

        if not auth_user:
            return False, "User not found."

        if not skip_validation:
            if not self.__verify_user(auth_user):
                return False, "User not found."

        new_secret = self.hash_password(password=new_password, algorithm=AuthDb.DEFAULT_HASH_ALGORITHM)
        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("UPDATE auth SET password = ?, salt = ?, algorithm = ? WHERE uid = ?",
                               (new_secret.password_hash, new_secret.salt, new_secret.algorithm, auth_user.uid))
                self.db.commit()
        except:
            return False, "Database Error!"

        return True, "OK!"

    def unregister(self, skip_validation: bool = False) -> Tuple[bool, str]:
        """Unregister an existing username."""
        self.ping()

        if self.migration_version() < AuthDb.MIN_VERSION:
            return False, "Empty or not updated database."

        auth_user = self.__find_user()

        if not auth_user:
            return False, "User not found."

        if not skip_validation:
            if not self.__verify_user(auth_user):
                return False, "User not found."

        # already had auth_user, can just update status or delete user
        # right now, we just flag it as expired.
        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("UPDATE auth SET status = ? WHERE uid = ?", (AuthDb.FLAG_EXPIRE, auth_user.uid))
                self.db.commit()
        except:
            return False, "Database error."

        return True, "OK"

    def cleanup(self):
        self.ping()

        try:
            with closing(self.db.cursor()) as cursor:
                # first, scan the whole auth table, finding all inactive users
                cursor.execute("""UPDATE auth
                                  SET status = ?
                                  WHERE last_activity = 0
                                  AND strftime('%s', 'now') - strftime('%s', created_at) > retention_deadline
                                  AND status = ?""", (AuthDb.FLAG_RETENTION, AuthDb.FLAG_OK))
                cursor.execute("""UPDATE auth
                                  SET status = ?
                                  WHERE last_activity <> 0
                                  AND strftime('%s', 'now') - last_activity > retention_deadline
                                  AND status = ?""", (AuthDb.FLAG_RETENTION, AuthDb.FLAG_OK))
                self.db.commit()

                # then from everyone in retention, mark everyone that's overdue as expire
                cursor.execute("""UPDATE auth
                                  SET status = ?
                                  WHERE last_activity = 0
                                  AND strftime('%s', 'now') - strftime('%s', created_at) > 2 * retention_deadline
                                  AND status = ?""", (AuthDb.FLAG_EXPIRE, AuthDb.FLAG_RETENTION))
                cursor.execute("""UPDATE auth
                                  SET status = ?
                                  WHERE last_activity <> 0
                                  AND strftime('%s', 'now') - last_activity > 2 * retention_deadline
                                  AND status = ?""", (AuthDb.FLAG_EXPIRE, AuthDb.FLAG_RETENTION))
                self.db.commit()
        except:
            return False

        try:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("DELETE FROM auth WHERE status = ?", (AuthDb.FLAG_EXPIRE,))
                self.db.commit()
        except:
            return False
        return True

    def list(self) -> Tuple[bool, str]:
        self.ping()
        ret = []

        try:
            with closing(self.db.cursor()) as cursor:
                if self.user:
                    if not self.user.name:
                        return False, "Bad username"
                    cursor.execute("""SELECT uid, uname, strftime("%s", created_at) AS created_at, status, retention_deadline, last_activity
                                      FROM auth
                                      WHERE uname = ? ORDER BY uid""", (self.user.name,))
                else:
                    cursor.execute("""SELECT uid, uname, strftime("%s", created_at) AS created_at, status, retention_deadline, last_activity
                                      FROM auth ORDER BY uid""")

                while True:
                    temp = cursor.fetchone()
                    if not temp:
                        break

                    ret.append(AuthUser(
                        uid = temp["uid"],
                        uname = temp["uname"],
                        password = None,
                        salt = None,
                        algorithm = None,
                        status = temp["status"],
                        created_at = datetime.utcfromtimestamp(int(temp["created_at"])).strftime("%Y-%m-%d %H:%M:%S"),
                        retention_deadline = temp["retention_deadline"],
                        last_activity = 0 if not temp["last_activity"] else datetime.utcfromtimestamp(temp["last_activity"]).strftime("%Y-%m-%d %H:%M:%S"),
                    ))

                return True, ret
        except:
            return False, "Database error."

    @staticmethod
    def filter_username(username: str) -> str:
        """Return normalized username from given username."""
        if isinstance(username, str):
            username = username.strip()
            username = "".join([c if c in AuthDb.USERNAME_CHARACTERS else AuthDb.NORMALIZED_CHARACTER for c in username])

            if username and len(username) > AuthDb.MIN_USERNAME_LEN and len(username) <= AuthDb.MAX_USERNAME_LEN:
                return username

        return None

    @staticmethod
    def filter_password(password: str) -> str:
        """Return normalized password from given password."""
        if isinstance(password, str):
            password = password.strip()
            password = "".join([c if c not in AuthDb.PASSWORD_BAD_CHARACTERS else AuthDb.NORMALIZED_CHARACTER for c in password])

            if password and len(password) > AuthDb.MIN_PASSWORD_LEN and len(password) <= AuthDb.MAX_PASSWORD_LEN:
                return password

        return None

    def migration(self):
        migration_methods = [m for m in dir(self) if m.startswith(AuthDb.MIGRATION_PREFIX)]
        for method in migration_methods:
            m = getattr(self, method, None)
            if callable(m):
                m()

    def migration_version(self):
        self.ping()
        version = 0

        with closing(self.db.cursor()) as cursor:
            cursor.execute("PRAGMA user_version")
            version = cursor.fetchone()[0]

        return version

    def _migration_rev_0000(self):
        check_version = 1
        self.ping()

        if self.migration_version() < check_version:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("BEGIN EXCLUSIVE TRANSACTION")
                cursor.execute("""CREATE TABLE IF NOT EXISTS auth (
                    uid BLOB PRIMARY KEY,
                    uname TEXT UNIQUE NOT NULL,
                    password BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    algorithm INT NOT NULL DEFAULT 0,
                    created_at INT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    status INT NOT NULL DEFAULT 0,
                    retention_deadline INT NOT NULL DEFAULT 604800
                )""")
                cursor.execute("PRAGMA user_version = {0}".format(check_version))
                cursor.execute("COMMIT TRANSACTION")

    def _migration_rev_0001(self):
        check_version = 2
        self.ping()

        if self.migration_version() < check_version:
            with closing(self.db.cursor()) as cursor:
                cursor.execute("BEGIN EXCLUSIVE TRANSACTION")
                cursor.execute("ALTER TABLE auth ADD COLUMN last_activity INT NOT NULL DEFAULT 0")
                cursor.execute("PRAGMA user_version = {0}".format(check_version))
                cursor.execute("COMMIT TRANSACTION")
