"""
Code to try and crash service.
"""
import socket
import ssl
import time
import os
import requests
import random

PORT_NUM_CONTROL = int(os.getenv("PORT_NUM_CONTROL", "43301"))
PORT_NUM_PEER_SSL = int(os.getenv("PORT_NUM_PEER_SSL", "443"))
IP_ADDRESS = os.getenv("IP_ADDRESS", "127.0.0.1")

# TLS certificate paths
WRONG_SERVER_CERT = os.getenv("LSM_CI_WRONG_SERVER_CERT",
                              "wrong_server_cert.pem")
WRONG_CLIENT_CERT = os.getenv("LSM_CI_WRONG_CLIENT_CERT",
                              "wrong_client_cert.pem")
WRONG_CLIENT_KEY = os.getenv("LSM_CI_WRONG_CLIENT_KEY", "wrong_client_key.pem")

SERVER_CERT_PEM = os.getenv("LSM_CI_SERVER_CERT_PEM", "server_cert.pem")
CLIENT_CERT_PEM = os.getenv("LSM_CI_CLIENT_CERT_PEM", "client_cert.pem")
CLIENT_KEY_PEM = os.getenv("LSM_CI_CLIENT_KEY_PEM", "client_key.pem")


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
        print(f"failing_ssl: {e}")

    time.sleep(0.2)


def invalid_ssl_cert():
    """
    Use a cert, just not the correct one.
    :return:  None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Created socket!")
        ssl_sock = ssl.wrap_socket(
            s,
            ca_certs=WRONG_SERVER_CERT,
            cert_reqs=ssl.CERT_REQUIRED,
            certfile=WRONG_CLIENT_CERT,
            keyfile=WRONG_CLIENT_KEY,
        )
        print("Have ssl_sock!")
        ssl_sock.connect((IP_ADDRESS, PORT_NUM_PEER_SSL))
        print("invalid_ssl_cert: connected")
        time.sleep(3)
        ssl_sock.close()
    except Exception as e:
        print(f"invalid_ssl_cert: {e}")

    time.sleep(0.2)


def valid_ssl_cert():
    """
    Use the correct cert
    :return:  None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Created socket!")
        ssl_sock = ssl.wrap_socket(
            s,
            ca_certs=SERVER_CERT_PEM,
            cert_reqs=ssl.CERT_REQUIRED,
            certfile=CLIENT_CERT_PEM,
            keyfile=CLIENT_KEY_PEM,
        )
        print("Have ssl_sock!")
        ssl_sock.connect((IP_ADDRESS, PORT_NUM_PEER_SSL))
        print("valid_ssl_cert: connected")
        time.sleep(5)
        ssl_sock.close()
    except Exception as e:
        print(f"valid_ssl_cert: {e}")

    time.sleep(0.2)


def open_write():
    """
    Write a large amount of data.
    :return:
    """

    d = "#" * 64
    to_send = d.encode("utf-8")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((IP_ADDRESS, PORT_NUM_CONTROL))
        s.sendall(to_send)
        print("open_write: connected->written")
        s.close()
    except Exception as e:
        print(f"open_write: {e}")

    time.sleep(0.2)


def uri_control(path):
    return f"http://{IP_ADDRESS}:{PORT_NUM_CONTROL}/{path}"


def gets():

    for n in ["nodes", "stats", "queue", "processing", "completed"]:
        uri = uri_control(n)
        print(f"uri = {uri}")
        response = requests.get(url=uri)
        print(f"status code = {response.status_code}")
        print(response.text)


while True:
    tests = [gets, failing_ssl, open_write, invalid_ssl_cert, valid_ssl_cert]
    the_one = tests[random.randrange(0, len(tests))]
    the_one()
