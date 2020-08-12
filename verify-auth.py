#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# see https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
#
# when OpenVPN requests for authentication verification via auth-user-pass-verify with via-file method,
# it'll write username and password in a temp file, and set it as an argument to your specified script.
#
# most distro nowadays uses tmpfs for /tmp, so default tmp-file config for OpenVPN is safe enough,
# but you should recheck it for security, preventing username:password pair to ever written to hard disk.
#
# The script should examine the username and password, returning a success exit code (0) if the client’s
# authentication request is to be accepted, or a failure code (1) to reject the client.
#
# To protect against a client passing a maliciously formed username or password string, the username
# string must consist only of these characters: alphanumeric, underbar (‘_’), dash (‘-‘), dot (‘.’),
# or at (‘@’). The password string can consist of any printable characters except for CR or LF.
# Any illegal characters in either the username or password string will be converted to underbar (‘_’).

import sys
import sqlite3

from common import User, AuthDb

# temporary filename is in first argument.
tmp_fn = sys.argv[1]

username, password = None, None
with open(tmp_fn, "r") as tmp_fp:
    username = tmp_fp.readline()
    password = tmp_fp.readline()

# now we've set username and password.
current_user = User(name=username, password=password)

# log her in.
auth_db = AuthDb()
result, extra = auth_db.with_user(current_user).auth()

if not result:
    print(extra, file=sys.stderr)
    sys.exit(1)

print("OK!")
sys.exit(0)
