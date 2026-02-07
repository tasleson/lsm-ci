#!/usr/bin/env python3
import ssl
import socket
import threading
import time
import traceback
import sys
import os

HOST = "localhost"
PORT = 43201
TIMEOUT = 10

# TLS certificate paths
CA = os.getenv("LSM_CI_CA_CERT", "../certs/ca.pem")
CLIENT_CERT = os.getenv("LSM_CI_CLIENT_CERT", "../certs/client.crt")
CLIENT_KEY = os.getenv("LSM_CI_CLIENT_KEY", "../certs/client.key")

BAD_CA = os.getenv("LSM_CI_BAD_CA_CERT", "../certs/bad_ca.pem")
BAD_CLIENT_CERT = os.getenv("LSM_CI_BAD_CLIENT_CERT", "../certs/bad_client.crt")
BAD_CLIENT_KEY = os.getenv("LSM_CI_BAD_CLIENT_KEY", "../certs/bad_client.key")

EXPIRED_CLIENT_CERT = os.getenv("LSM_CI_EXPIRED_CLIENT_CERT",
                                "../certs/bad_expired_client.crt")
EXPIRED_CLIENT_KEY = os.getenv("LSM_CI_EXPIRED_CLIENT_KEY",
                               "../certs/bad_expired_client.key")

SERVER_HOSTNAME = os.getenv("LSM_CI_SERVER_HOSTNAME", "ci.asleson.org")


def attempt(name,
            context_builder,
            server_hostname=None,
            expected_success=False,
            retries=3):
    if server_hostname is None:
        server_hostname = SERVER_HOSTNAME
    print(f"\n==> TEST: {name}")

    for attempt_num in range(retries):
        try:
            ctx = context_builder()
            with socket.create_connection((HOST, PORT),
                                          timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock,
                                     server_hostname=server_hostname) as ssock:
                    data = ssock.recv()
                    print(f"We read {data.decode('utf-8')} from server!")

                    cert = ssock.getpeercert(
                    )  # This will work even if the server closes connection
                    if not expected_success:
                        print("✖ We expected not to connect, but we did!")
                        sys.exit(1)
                    print("✔ connected")
                    print("server subject:", cert.get("subject"))
                    return  # Success, exit retry loop
        except socket.timeout as e:
            if attempt_num < retries - 1 and expected_success:
                print(f"⟳ Timeout, retrying ({attempt_num + 1}/{retries})")
                time.sleep(0.5)
                continue
            # Last retry or unexpected timeout
            if expected_success:
                print("✖ failed:", repr(e))
                sys.exit(1)
            print(f"✔ failed as expected! {repr(e)}")
            return
        except Exception as e:
            if expected_success:
                print("✖ failed:", repr(e))
                sys.exit(1)
            print(f"✔ failed as expected! {repr(e)}")
            return


# ---------- CONTEXT BUILDERS ----------


def valid_context():
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA,
    )
    ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    ctx.check_hostname = True
    return ctx


def no_client_cert():
    return ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA,
    )


def wrong_ca():
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=BAD_CA,
    )
    ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    return ctx


def wrong_client_cert():
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA,
    )
    ctx.load_cert_chain(BAD_CLIENT_CERT, BAD_CLIENT_KEY)
    return ctx


def expired_client_cert():
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA,
    )
    ctx.load_cert_chain(EXPIRED_CLIENT_CERT, EXPIRED_CLIENT_KEY)
    return ctx


def hostname_mismatch():
    ctx = valid_context()
    return ctx


def corrupted_cert():
    ctx = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA,
    )
    # intentionally load wrong file
    ctx.load_cert_chain(CLIENT_CERT, CLIENT_CERT)
    return ctx


# ---------- PARALLEL STRESS ----------

# Global flag to track failures in worker threads
failed = False
failed_lock = threading.Lock()


def stress_worker(i):
    global failed
    try:
        attempt(f"PARALLEL-{i}", valid_context, expected_success=True)
    except SystemExit:
        with failed_lock:
            failed = True
    except Exception:
        traceback.print_exc()
        with failed_lock:
            failed = True


def stress():
    global failed
    print("\n==> PARALLEL HANDSHAKE STRESS")
    threads = []
    for i in range(200):
        t = threading.Thread(target=stress_worker, args=(i, ))
        t.start()
        threads.append(t)
        time.sleep(0.01)  # Stagger thread startup to avoid overwhelming server

    for t in threads:
        t.join()

    if failed:
        print("✖ Parallel stress test failed")
        sys.exit(1)

    print("\n==> RAPID RECONNECT STRESS")
    for i in range(200):
        attempt(f"RECONNECT-{i}", valid_context, expected_success=True)
        time.sleep(0.1)


if __name__ == "__main__":

    # ---------- EXECUTION ----------
    while True:
        attempt("VALID CERT", valid_context, expected_success=True)
        attempt("NO CLIENT CERT", no_client_cert)
        attempt("WRONG CA", wrong_ca)
        attempt("WRONG CLIENT CERT", wrong_client_cert)
        attempt("EXPIRED CLIENT CERT", expired_client_cert)
        attempt("HOSTNAME MISMATCH",
                hostname_mismatch,
                server_hostname="wrong.example.com")
        attempt("CORRUPTED CERT", corrupted_cert)

        stress()
