#!/usr/bin/env python3
"""
Test development server.
"""

import socket
import ssl
import testlib
import traceback
import sys
import os

# TLS certificate paths
SERVER_CERT_PEM = os.getenv("LSM_CI_SERVER_CERT_PEM", "server_cert.pem")
SERVER_KEY_PEM = os.getenv("LSM_CI_SERVER_KEY_PEM", "server_key.pem")
CLIENT_CERT_PEM = os.getenv("LSM_CI_CLIENT_CERT_PEM", "client_cert.pem")

bindsocket = socket.socket()
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bindsocket.bind(("", 8675))
bindsocket.listen(5)

while True:

    print("Waiting for a client...")
    new_socket, from_addr = bindsocket.accept()
    print("Accepted a connection from %s" % str(from_addr))

    connection = ssl.wrap_socket(
        new_socket,
        server_side=True,
        certfile=SERVER_CERT_PEM,
        keyfile=SERVER_KEY_PEM,
        ca_certs=CLIENT_CERT_PEM,
        cert_reqs=ssl.CERT_REQUIRED,
    )

    in_line = "start"

    t = testlib.Transport(connection)

    try:
        while in_line:
            in_line = input("control> ")
            if in_line:
                args = in_line.split()

                if len(args) > 1:
                    t.write_msg(testlib.Request(args[0], args[1:]))
                else:
                    t.write_msg(testlib.Request(args[0]))

                resp = t.read_msg()
                print(resp)
    except KeyboardInterrupt:
        bindsocket.shutdown(socket.SHUT_RDWR)
        bindsocket.close()
        sys.exit(1)
    except EOFError:
        pass
    except Exception:
        traceback.print_exc(file=sys.stdout)
    finally:
        connection.close()
