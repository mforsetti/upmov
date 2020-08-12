#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Basic username and password authentication script for OpenVPN's auth-user-pass-verify
#
# see https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
#
# To protect against a client passing a maliciously formed username or password string, the username
# string must consist only of these characters: alphanumeric, underbar (‘_’), dash (‘-‘), dot (‘.’),
# or at (‘@’). The password string can consist of any printable characters except for CR or LF.
# Any illegal characters in either the username or password string will be converted to underbar (‘_’).

# upmov.py register --user username
# upmov.py unregister --user username
# upmov.py validate --user username
# upmov.py initialize
# upmov.py cleanup
# upmov.py list --user username
# upmov.py chpass --user username

import sqlite3
import sys
import os
import argparse
import getpass
import uuid

from common import DATA_DIR, AuthDb, DB_FILE, User

__version__ = "0.1"

def out(tag, message):
    print("{0} {1}".format(tag, message))

def error(message):
    out("[!]", message)

def info(message):
    out("[*]", message)

def debug(message):
    out("[.]", message)

def process_start(message):
    print("[>] {0}".format(message), end="")

def process_end(result):
    print(" [ OK ]" if result else " [ !! ]")

def get_args():
    argument_parser = argparse.ArgumentParser(description="Username and password management for OpenVPN.")
    argument_parser.add_argument("COMMAND", choices=["register", "unregister", "validate", "initialize", "cleanup", "list", "chpass"], help="Action to do to username/password database.")
    argument_parser.add_argument("--user", "-u", default=None, metavar="USERNAME", help="User to apply action to.")
    argument_parser.add_argument('--force', '-f', action="store_true", help="Force action, removing password verification from some actions.")
    argument_parser.add_argument("--version", "-v", action="version", version=__version__)

    return argument_parser.parse_args()

def ask_password(prompt="Password: "):
    pwd = getpass.getpass(prompt=prompt)
    return pwd

def ask_username():
    uname = input("Username: ")
    return uname

def check_initialize() -> bool:
    if not os.path.isdir(DATA_DIR):
        return False

    auth_db = AuthDb()
    if auth_db.migration_version() == 0:
        return False

    return True

def main():
    args = get_args()
    if args.COMMAND == "initialize":
        process_start("Initializing upmov...")

        try:
            if not os.path.isdir(DATA_DIR):
                os.umask(0o022)
                os.makedirs(DATA_DIR, mode=0o755, exist_ok=True)
        except:
            process_end(False)
            error("Cannot create data directory for upmov.py")
            error("Please create a data directory in [ {0} ], and grant write access to user running upmov.py.".format(DATA_DIR))
            return 1

        try:
            auth_db = AuthDb()
            auth_db.migration()
        except:
            process_end(False)
            error("Cannot initialize upmov.py database.")
            error("Please make sure data directory [ {0} ] is writable by user running upmov.py,".format(DATA_DIR))
            error("and there's enough disk space to store user database.")
            return 1

        process_end(True)
        info("Created data file in {0}".format(DB_FILE))
    else:
        if not check_initialize():
            error("upmov not yet initialized.")
            error("Please run `upmov.py initialize' first!")
            return 1

        if args.COMMAND == "register":
            if not args.user:
                args.user = ask_username()

            # ask for password
            password = ask_password()
            confirm_password = ask_password("Confirm Password: ")

            if not password == confirm_password:
                error("Password mismatch.")
                return 1

            auth_db = AuthDb()
            user = User(name=args.user, password=password)
            result, extra = auth_db.with_user(user).register()

            if not result:
                error(extra)
                return 1

            info("Registration successful.")
        elif args.COMMAND == "unregister":
            if not args.user:
                args.user = ask_username()

            password = None
            if not args.force:
                password = ask_password()

            auth_db = AuthDb()
            user = User(name=args.user, password=password)
            result, extra = auth_db.with_user(user).unregister(skip_validation=args.force)

            if not result:
                error(extra)
                return 1
            info("User [{0}] deleted.".format(args.user))
        elif args.COMMAND == "validate":
            if not args.user:
                args.user = ask_username()

            # ask for password
            password = ask_password()

            auth_db = AuthDb()
            user = User(name=args.user, password=password)
            result, extra = auth_db.with_user(user).auth(validate=True)

            if not result:
                error(extra)
                return 1
            else:
                info("Username/password pair for user [ {0} ] successfully validated.".format(args.user))
        elif args.COMMAND == "list":
            auth_db = AuthDb()

            if args.user:
                auth_db = auth_db.with_user(User(name=args.user, password=None))

            result, extra = auth_db.list()

            if not result:
                error(extra)
                return 1

            if not extra:
                info("No user registered yet.")
            else:
                for user in extra:
                    info("User: {1} [ID: {{{0}}}] ".format(uuid.UUID(bytes=user.uid), user.uname))
                    info("Registered at: {0}".format(user.created_at) + (" (Last activity: {0})".format(user.last_activity) if user.last_activity else ""))
                    info("Status: {0}".format("OK" if user.status == AuthDb.FLAG_OK else ("EXPIRED/DELETED" if user.status == AuthDb.FLAG_EXPIRE else "RETENTION")))
                    print()
                info("End of list")
        elif args.COMMAND == "cleanup":
            process_start("Running database cleanup...")
            auth_db = AuthDb()

            if not auth_db.cleanup():
                process_end(False)
                return 1

            process_end(True)
        elif args.COMMAND == "chpass":
            if not args.user:
                args.user = ask_username()

            password = None
            if not args.force:
                password = ask_password()

            new_password = ask_password("New Password:")
            confirm_password = ask_password("Confirm New Password:")

            if not new_password == confirm_password:
                error("Password mismatch.")
                return 1

            user = User(name=args.user, password=password)
            auth_db = AuthDb()
            result, extra = auth_db.with_user(user).change_password(new_password=new_password, skip_validation=args.force)

            if not result:
                error(extra)
                return 1

            info("Password for user [ {0} ] successfully updated.".format(args.user))
        else:
            error("upmov should not reach here.")
            error("Please file a bug report to upmov maintainer!")
            return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
