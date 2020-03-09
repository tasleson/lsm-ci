"""
Code to try and crash service.
"""
import socket
import ssl
import time
import os


PORT_NUM_CONTROL = os.getenv('PORT_NUM_CONTROL', "43301")
PORT_NUM_PEER_SSL = os.getenv('PORT_NUM_PEER_SSL', "443")
IP_ADDRESS = os.getenv("IP_ADDRESS", "127.0.0.1")


def failing_ssl():
    """
    Failing ssl connect
    :return: None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(s)

        ssl_sock.connect((IP_ADDRESS, PORT_NUM_PEER_SSL))
        print("failing_ssl: connected")
        ssl_sock.close()
    except Exception as e:
        print("failing_ssl: %s" % str(e))

    time.sleep(0.2)


def open_write():
    """
    Write a large amount of data.
    :return:
    """

    d = '#' * 64
    to_send = d.encode("utf-8")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((IP_ADDRESS, PORT_NUM_CONTROL))
        s.sendall(to_send)
        print("open_write: connected->written")
        s.close()
    except Exception as e:
        print("open_write: %s" % str(e))

    time.sleep(0.2)


while True:
    failing_ssl()
    open_write()
