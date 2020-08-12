# upmov

## About
**U**sername and **P**assword **M**anager for **O**pen**V**PN

A simple SQLite-backed username and password manager and challenge verificator for `auth-user-pass` OpenVPN.

## Requirements
* Linux/Unix-based server
* OpenVPN Server with `auth-user-pass` set
* Python 3.6+

This script is designed without extra packages required, so a standard Python 3.6+ installation should be able to run this script.

## Usage
### Username and Password Management
1. Clone this repository.

    ```bash
    $ git clone https://github.com/miguelforsetti/upmov
    ```

1. Install `python3`, either from your distro's repository or compiling it manually.

    ```bash
    $ yum install python36
    ```

1. `chmod` required scripts.

    ```bash
    $ cd upmov
    $ chmod a+x upmov.py verify-auth.py
    ```

1. Initialize upmov data directory

    ```bash
    $ ./upmov.py initialize
    ```

    **Note**: if you encounter this error:

    ```
    Cannot create data directory for upmov.py
    ```

    create upmov data directory on your own and assign permissions to it, then re-initialize upmov data directory again.

    ```bash
    $ mkdir -p /var/lib/upmov
    $ chown $USER /var/lib/upmov
    $ chmod 755 /var/lib/upmov
    $ ./upmov.py initialize
    ```

1. Start adding your users

    ```bash
    $ ./upmov.py register --user user1
    $ ./upmov.py register --user user2
    ```

1. To get more information about this script, run it with `--help`.

    ```bash
    $ ./upmov.py --help
    ```

### OpenVPN Authentication Script
1. Enable OpenVPN Password authentication in OpenVPN server configuration.

    ```conf
    # in server.conf

    ...
    auth-user-pass
    auth-user-pass-verify /path/to/upmov/verify-auth.py via-file
    username-as-common-name
    # note that client-cert-not-required is deprecated in OpenVPN 2.4 and will be removed in 2.5
    client-cert-not-required
    verify-client-cert none
    ...
    ```
    `/path/to/upmov/verify-auth.py` obviously points to the location of `verify-auth.py` in upmov directory.

1. Make sure you already have registered users in your upmov database.

1. Restart your OpenVPN server.
    ```bash
    $ sudo systemctl openvpn-server@server.service restart
    ```

1. Try to login from your client with username and password.

## License
upmov is licensed under the terms of the MIT license. Full text of the license can be read under LICENSE file in project root directory.

## Copyrights and Trademarks
All trademarks, copyrights, product names and logos mentioned are property of their respective owners. All rights reserved.

## Footnotes
1. [OpenVPN - Using Alternative Authentication Methods](https://openvpn.net/community-resources/using-alternative-authentication-methods/)
1. [OpenVPN - Reference manual for OpenVPN 2.4](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/) *see auth-user-pass, auth-user-pass-verify, username-as-common-name, client-cert-not-required, and verify-client-cert*