#  See: https://github.com/tasleson/lsm-ci/blob/master/LICENSE

import json
import hashlib
import os
import socket
import ssl
import datetime
import time
import sys
import threading
import select
import traceback
import multiprocessing


PORT = 443

hs = os.getenv("LSM_CI_HASH_SALT", "")

RUN = multiprocessing.Value('i', 1)


def md5(t):
    h = hashlib.md5()
    h.update(t.encode("utf-8"))
    h.update(hs.encode('utf-8'))
    return h.hexdigest()


class Request(object):

    def __init__(self, method, args=None):
        self.method = method
        self.args = args

    def serialize(self):
        return json.dumps(dict(method=self.method, args=self.args))

    def __str__(self):
        return self.serialize()


class Response(object):

    def __init__(self, result, ec, err_msg):
        self.result = result
        self.ec = int(ec)
        self.err_msg = err_msg

    def serialize(self):
        return json.dumps(dict(ec=self.ec, err_msg=self.err_msg,
                               result=self.result))

    def __str__(self):
        return self.serialize()


def deserialize(json_str):
    package = json.loads(json_str)

    if 'method' in package:
        return Request(**package)
    else:
        return Response(**package)


class Transport(object):

    HDR_LEN = 10 + 32

    def __init__(self, s):
        self.s = s

    def _read_all(self, l):
        # Reads the specified number of bytes from socket
        if l < 1:
            raise ValueError("Trying to read less than 1 byte!")

        data = bytearray()
        while len(data) < l:
            amount_read = self.s.recv(l - len(data))
            if not amount_read:
                raise IOError("Shorted read")
            data += amount_read

        return data.decode("utf-8")

    def read_msg(self):
        # Read the header, then the payload, validate the payload, parse and
        # return the Request or response

        hdr = self._read_all(self.HDR_LEN)
        payload_len, signature = int(hdr[:10]), hdr[10:]

        if payload_len > 2**28:
            raise IOError("Payload len too large %d" % payload_len)

        payload = self._read_all(payload_len)

        if md5(payload) != signature:
            raise IOError("Incorrect signature!")

        return deserialize(payload)

    def write_msg(self, msg):
        # Message will have the following format
        # 10 digit payload length
        # 32 character payload md5
        # payload

        serialized_msg = msg.serialize()
        digest = md5(serialized_msg)

        to_send = "%s%s%s" % \
                  (str.zfill(str(len(serialized_msg)), 10), digest,
                   serialized_msg)
        self.s.sendall(bytes(to_send.encode('utf-8')))


def p(msg):
    ts = datetime.datetime.fromtimestamp(
        time.time()).strftime('%Y-%m-%d %H:%M:%S')
    print("%s:%d:%s" % (ts, os.getpid(), msg))
    sys.stdout.flush()


class TestNode(object):

    def __init__(self, server_ip, port=PORT):
        self.server_ip = server_ip
        self.port = port
        self.s = None
        self.t = None

    def connect(self):

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s = ssl.wrap_socket(self.s,
                                     ca_certs="server_cert.pem",
                                     cert_reqs=ssl.CERT_REQUIRED,
                                     certfile="client_cert.pem",
                                     keyfile="client_key.pem"
                                     )

            self.s.connect((self.server_ip, self.port))

            self.t = Transport(self.s)
        except Exception as e:
            # Log the error
            p("connect exception: %s" % str(e))
            return False

        return True

    def wait_for_request(self):
        return self.t.read_msg()

    def return_response(self, resp):
        self.t.write_msg(resp)

    def disconnect(self):
        # noinspection PyBroadException
        try:
            self.s.close()
        except Exception:
            pass
        self.s = None
        self.t = None


class Node(object):

    READY = 1
    UNUSABLE = 2

    def _rpc(self, request, args=None):
        resp = None
        if self.state != Node.UNUSABLE:
            try:
                self.t.write_msg(Request(request, args))
                resp = self.t.read_msg()
            except IOError:
                self.state = Node.UNUSABLE

        return resp

    def __init__(self, accepted_socket, from_addr):
        self._state = Node.READY
        self.s = accepted_socket
        self.t = Transport(accepted_socket)
        (self.client_ip, self.client_port) = from_addr
        self.lock = threading.RLock()

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        if self._state != value:
            if value == Node.UNUSABLE:
                p('Node %s:%d now unavailable!' %
                  (self.client_ip, self.client_port))
        self._state = value

    def close(self):
        with self.lock:
            # noinspection PyBroadException
            try:
                self.s.close()
            except Exception:
                pass
            finally:
                self.state = Node.UNUSABLE

    def verify(self):
        rc = False
        with self.lock:
            if self.state == Node.READY:
                resp = self._rpc('ping')
                if resp and resp.ec == 200:
                    rc = True
                else:
                    self.state = Node.UNUSABLE
        return rc

    def replace(self, other):
        with self.lock:
            with other.lock:
                # Close this connection
                self.close()
                self.state = other.state
                self.s = other.state
                self.t = other.t
                self.client_ip = other.client_ip
                self.client_port = other.client_port

    def arrays(self):
        with self.lock:
            resp = self._rpc('arrays')
            if resp and resp.ec == 200:
                return resp.result
            else:
                p("Error when calling 'arrays' %s" % str(resp))
            return []

    def arrays_running(self):
        with self.lock:
            resp = self._rpc('running')
            if resp and resp.ec == 200:
                # Returns an array of dicts. eg.
                # [{"STATUS": "RUNNING",
                # "ID": "simulator",
                # "JOB_ID": "czthgpztdcvcvqjrgcdcwerppctodtdc",
                # "PLUGIN": "sim"}]
                return resp.result
            else:
                p("Error when getting array list %s" % str(resp))

            return []

    def jobs(self):
        with self.lock:
            resp = self._rpc('jobs')
            if resp and resp.ec == 200:
                return resp.result
            return []

    def job_completion(self, job_id):
        with self.lock:
            resp = self._rpc('job_completion', (job_id,))
            if resp and resp.ec == 200:
                output = json.loads(resp.result)['OUTPUT']
                return output
            return None

    def job_delete(self, job_id):
        with self.lock:
            resp = self._rpc('job_delete', (job_id,))
            if resp and resp.ec != 200:
                p("Error: Unable to delete job id = %s resp = %s" %
                    (job_id, str(resp)))

    def start_test(self, clone_url, branch, array_id):
        with self.lock:
            resp = self._rpc('job_create', (clone_url, branch, array_id))
            if resp and resp.ec == 201:
                return resp.result
            else:
                p('Error: when creating job: %s' % str(resp))
            return None


class NodeManager(object):
    """
       Thread safe object for handling all the disjoint test nodes

       Notes:
        - The clients can come and go at anytime
        - The clients available at the start of the test will be expected to
          be present through the duration of the test.  New clients that connect
          during the duration of the test will not be utilized.  Clients that
          fall out during the test will be logged as failing with status on
          github stating as much
    """

    def __init__(self, listening_ip='', port=PORT):
        self.ip = listening_ip
        self.port = port
        self.lock = threading.RLock()
        self.known_clients = {}

    def start(self):
        thread = threading.Thread(target=NodeManager.main_event_loop,
                                  name="Node Manager", args=(self,))
        thread.start()

    def nodes(self):
        rc = []
        with self.lock:
            for i in self.known_clients.values():
                # Make sure the node is responsive before adding it to the list
                # of nodes to run tests against
                if i.verify():
                    rc.append(i)

        return rc

    @staticmethod
    def main_event_loop(node_mgr):
        # Setup the listening socket
        bindsocket = socket.socket()
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind((node_mgr.ip, node_mgr.port))
        bindsocket.listen(5)

        while RUN.value:
            # noinspection PyBroadException
            try:
                ready = select.select([bindsocket], [], [], 15)

                for r in ready[0]:
                    new_socket, from_addr = bindsocket.accept()
                    p("Accepted a connection from %s" % str(from_addr))

                    connection = ssl.wrap_socket(new_socket,
                                                 server_side=True,
                                                 certfile="server_cert.pem",
                                                 keyfile="server_key.pem",

                                                 ca_certs="client_cert.pem",
                                                 cert_reqs=ssl.CERT_REQUIRED)

                    with node_mgr.lock:
                        # If we already had this client, close previous and
                        # update with new.  We are expecting only one connection
                        # from any given unique IP.  We are doing this so if the
                        # connection fails we can re-associate to the same test
                        # node.  It is possible both ends are up and functional
                        # and the network goes down/up etc.
                        nc = Node(connection, from_addr)

                        client_ip = from_addr[0]
                        if client_ip in node_mgr.known_clients:
                            node_mgr.known_clients[client_ip].replace(nc)
                        else:
                            node_mgr.known_clients[client_ip] = nc

                # If all the nodes are doing nothing, lets ping them to ensure
                # they still are present and responding
                with node_mgr.lock:
                    for i in node_mgr.known_clients.values():
                        i.verify()

            except KeyboardInterrupt:
                bindsocket.close()
                sys.exit(1)
            except:
                p(str(traceback.format_exc()))
        p('Exiting node manager thread...')


def get_client_socket(server_ip, port=PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ssl_sock = ssl.wrap_socket(s,
                               ca_certs="server_cert.pem",
                               cert_reqs=ssl.CERT_REQUIRED,

                               certfile="client_cert.pem",
                               keyfile="client_key.pem"
                               )

    ssl_sock.connect((server_ip, port))
    return ssl_sock
