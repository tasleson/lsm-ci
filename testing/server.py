#!/usr/bin/env python3
"""
Test development server.
"""

import socket
import ssl
import testlib
import traceback
import sys

bindsocket = socket.socket()
bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bindsocket.bind(('', 8675))
bindsocket.listen(5)

while True:

    print('Waiting for a client...')
    new_socket, from_addr = bindsocket.accept()
    print("Accepted a connection from %s" % str(from_addr))

    connection = ssl.wrap_socket(
        new_socket,
        server_side=True,
        certfile="server_cert.pem",
        keyfile="server_key.pem",
        ca_certs="client_cert.pem",
        cert_reqs=ssl.CERT_REQUIRED)

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
