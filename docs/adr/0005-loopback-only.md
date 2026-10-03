# The server listens on 127.0.0.1 only

Stackwell has no login: whoever can reach the port is the rep. It therefore never listens on any interface other than loopback, not even behind a flag. Remote or headless use goes through `--no-browser` plus an SSH tunnel (`ssh -L`).
