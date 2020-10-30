"""
Code to try and crash service.
"""
import socket
import ssl
import time
import os


PORT_NUM_CONTROL = int(os.getenv('PORT_NUM_CONTROL', "43301"))
PORT_NUM_PEER_SSL = int(os.getenv('PORT_NUM_PEER_SSL', "443"))
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


def invalid_ssl_cert():
    """
    Use a cert, just not the correct one.
    :return:  None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Created socket!")
        ssl_sock = ssl.wrap_socket(s,
                                   ca_certs="wrong_server_cert.pem",
                                   cert_reqs=ssl.CERT_REQUIRED,
                                   certfile="wrong_client_cert.pem",
                                   keyfile="wrong_client_key.pem")
        print("Have ssl_sock!")
        ssl_sock.connect((IP_ADDRESS, PORT_NUM_PEER_SSL))
        print("invalid_ssl_cert: connected")
        time.sleep(3)
        ssl_sock.close()
    except Exception as e:
        print("invalid_ssl_cert: %s" % str(e))

    time.sleep(0.2)


def valid_ssl_cert():
    """
    Use the correct cert
    :return:  None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Created socket!")
        ssl_sock = ssl.wrap_socket(s,
                                   ca_certs="server_cert.pem",
                                   cert_reqs=ssl.CERT_REQUIRED,
                                   certfile="client_cert.pem",
                                   keyfile="client_key.pem")
        print("Have ssl_sock!")
        ssl_sock.connect((IP_ADDRESS, PORT_NUM_PEER_SSL))
        print("valid_ssl_cert: connected")
        time.sleep(5)
        ssl_sock.close()
    except Exception as e:
        print("valid_ssl_cert: %s" % str(e))

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
    invalid_ssl_cert()
    valid_ssl_cert()
