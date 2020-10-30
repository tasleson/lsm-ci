"""
Shared code which is used in node_manager and node.

WARNING!  This file is auto updated from the node manager.  Any changes will
be lost when the client disconnects and reconnects.

This file is compatible with python2 and python3.

"""
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
import ctypes
import signal

# What port the clients will try to connect to
PORT = int(os.getenv("LSM_CI_CLIENT_PORT", 443))

hs = os.getenv("LSM_CI_HASH_SALT", "")

RUN = multiprocessing.Value('i', 1)

print_lock = threading.Lock()


def _file_data(file_name):
    with open(file_name, 'r') as file_to_check:
        file_contents = file_to_check.read()
    return file_contents


def file_md5(file_name):
    """
    Given a file name return md5 signature
    :param file_name: The name of the file
    :return: md5 signature.
    """
    return md5(_file_data(file_name))


def file_md5_and_data(file_name):
    """
    Returns the md5 and contents of file data.
    :param file_name: File name to open
    :return: (md5 file data, data)
    """
    fd = _file_data(file_name)
    return md5(fd), fd


def md5(t):
    """
    Calculate the md5 of data t
    :param t: Data to generate md5 for
    :return: md5 hex digest
    """
    h = hashlib.md5()
    h.update(t.encode("utf-8"))
    h.update(hs.encode('utf-8'))
    return h.hexdigest()


class Request(object):
    """
    Request class.
    """

    def __init__(self, method, args=None):
        self.method = method
        self.args = args

    def serialize(self):
        """
        Method to serialize the request.
        :return: JSON
        """
        return json.dumps(dict(method=self.method, args=self.args))

    def __str__(self):
        return self.serialize()


class Response(object):
    """
    Response class
    """

    def __init__(self, result, ec, err_msg):
        self.result = result
        self.ec = int(ec)
        self.err_msg = err_msg

    def serialize(self):
        """
        Method to serialize the response.
        :return: JSON
        """
        return json.dumps(
            dict(ec=self.ec, err_msg=self.err_msg, result=self.result))

    def __str__(self):
        return self.serialize()


def deserialize(json_str):
    """
    Given a JSON string, convert to Request or Response
    :param json_str: JSON to deserialize
    :return: Request or Response object
    """
    package = json.loads(json_str)

    if 'method' in package:
        return Request(**package)
    else:
        return Response(**package)


class Transport(object):
    """
    Handles the messages on the byte stream.
    """

    HDR_LEN = 10 + 32

    def __init__(self, s):
        self.s = s

    def _read_all(self, num_bytes):
        # Reads the specified number of bytes from socket
        if num_bytes < 1:
            raise ValueError("Trying to read less than 1 byte!")

        data = bytearray()
        while len(data) < num_bytes:
            amount_read = self.s.recv(num_bytes - len(data))
            if not amount_read:
                raise IOError("Shorted read")
            data += amount_read

        return data.decode("utf-8")

    def read_msg(self):
        """
        Read the header, then the payload, validate the payload, parse
        :return: The Request or Response.
        """
        hdr = self._read_all(self.HDR_LEN)
        payload_len, signature = int(hdr[:10]), hdr[10:]

        if payload_len > 2**28:
            raise IOError("Payload len too large %d" % payload_len)

        payload = self._read_all(payload_len)

        if md5(payload) != signature:
            raise IOError("Incorrect signature!")

        return deserialize(payload)

    def write_msg(self, msg):
        """
        Write the message out on the wire.
        :param msg: The request or response to serialize.
        :return: None
        """

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
    """
    Thread safe print which includes the thread ID in message.
    :param msg: Message to be printed
    :return: None
    """
    with print_lock:
        tid = ctypes.CDLL('libc.so.6').syscall(224)
        ts = datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y-%m-%d %H:%M:%S.%f')
        print("%s: %d:%d- %s" % (ts, os.getpid(), tid, msg))
        sys.stdout.flush()


def _try_close(s):
    # noinspection PyBroadException
    try:
        if s:
            s.close()
    except Exception:
        pass


class TestNode(object):
    """
    Class that handles the test node functionality.
    """

    def __init__(self,
                 server_ip,
                 port=PORT,
                 use_proxy=False,
                 proxy_is_ip=True,
                 proxy_host=None,
                 proxy_port=None):
        self.server_ip = server_ip
        self.port = port
        self.use_proxy = use_proxy
        if proxy_is_ip:
            self.proxy_host = proxy_host
        else:
            self.proxy_host = socket.gethostbyname(proxy_host)
        self.proxy_port = proxy_port
        self.s = None
        self.t = None

    def connect(self):
        """
        Connect to the node manager.
        :return: boolean
        """

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # We have pings that are happening every 15 seconds, lets wait
            # for up to 3 minutes waiting for one, otherwise we will error out
            # with a timeout on the read.
            self.s.settimeout(3 * 60)

            if self.use_proxy:
                p("Using proxy %s:%s" % (self.proxy_host, self.proxy_port))
                proxy_msg = 'CONNECT %s:%s HTTP/1.1\r\n\r\n' % \
                            (self.server_ip, self.port)
                self.s.connect((self.proxy_host, self.proxy_port))
                self.s.sendall(proxy_msg.encode("utf-8"))
                response = self.s.recv(8192)
                status = response.split()[1]

                if status != str(200):
                    raise IOError("Connection to proxy failed")

            self.s = ssl.wrap_socket(
                self.s,
                ca_certs="server_cert.pem",
                cert_reqs=ssl.CERT_REQUIRED,
                certfile="client_cert.pem",
                keyfile="client_key.pem")

            if self.use_proxy:
                self.s.do_handshake()
            else:
                self.s.connect((self.server_ip, self.port))

            self.t = Transport(self.s)
        except Exception as e:
            # Log the error
            p("connect exception: %s" % str(e))
            _try_close(self.s)
            return False

        return True

    def wait_for_request(self):
        """
        Blocks waiting for a request.
        :return: Request
        """
        return self.t.read_msg()

    def return_response(self, resp):
        """
        Returns a response.
        :param resp: Response to return
        :return: None
        """
        self.t.write_msg(resp)

    def disconnect(self):
        """
        Disconnect from node manager.
        :return: None
        """
        # noinspection PyBroadException
        _try_close(self.s)
        self.s = None
        self.t = None


class Node(object):
    """
    Represents a client for the node manager.
    """

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
        """
        State of the node
        :return: Node.READY, NODE.UNUSABLE
        """
        return self._state

    @state.setter
    def state(self, value):
        """
        Sets the state of the node
        :param value: New state
        :return: None
        """
        if self._state != value:
            if value == Node.UNUSABLE:
                p('Node %s:%d now unavailable!' % (self.client_ip,
                                                   self.client_port))
        self._state = value

    def close(self):
        """
        Close the connection to the node.
        :return: None
        """
        with self.lock:
            # noinspection PyBroadException
            _try_close(self.s)
            self.state = Node.UNUSABLE

    def verify(self):
        """
        Verifies the node by pinging it.
        :return: Boolean
        """
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
        """
        Replaces a connection with a node with this one.
        :param other: One to use as replacement.
        :return: None
        """
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
        """
        Finds out what arrays are on a node.
        :return: Array of information about storage arrays
        """
        with self.lock:
            resp = self._rpc('arrays')
            if resp and resp.ec == 200:
                return resp.result
            else:
                p("Error when calling 'arrays' %s" % str(resp))
            return []

    def increase_tmo(self):
        """
        Increase the timeout
        :return: None
        """
        # If we get here we have an authenticated client that is
        # responding so we will give it more time to avoid timeouts
        with self.lock:
            self.s.settimeout(3 * 60)

    def arrays_running(self):
        """
        Finds out status of running tests.
        :return: An array of dicts

        [{"STATUS": "RUNNING",
          "ID": "simulator",
          "JOB_ID": "czthgpztdcvcvqjrgcdcwerppctodtdc",
          "PLUGIN": "sim"}]
        """
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
        """
        Call the jobs method on node
        :return: Array
        """
        with self.lock:
            resp = self._rpc('jobs')
            if resp and resp.ec == 200:
                return resp.result
            return []

    def job_completion(self, job_id):
        """
        Get the result of the job id.
        :param job_id: ID of job
        :return: Result output
        """
        with self.lock:
            resp = self._rpc('job_completion', (job_id, ))
            if resp and resp.ec == 200:
                output = json.loads(resp.result)['OUTPUT']
                return output
            return None

    def job_delete(self, job_id):
        """
        Delete the job and associated data from node.
        :param job_id: ID of job
        :return: None
        """
        with self.lock:
            resp = self._rpc('job_delete', (job_id, ))
            if resp and resp.ec != 200:
                p("Error: Unable to delete job id = %s resp = %s" %
                  (job_id, str(resp)))
            else:
                p("Job %s deleted!" % job_id)

    def start_test(self, clone_url, branch, array_id):
        """
        Starts the test on the node.
        :param clone_url: github repo url
        :param branch: branch
        :param array_id: Array id to test
        :return: Job id or None
        """
        with self.lock:
            resp = self._rpc('job_create', (clone_url, branch, array_id))
            if resp and resp.ec == 201:
                return resp.result
            else:
                p('Error: when creating job: %s' % str(resp))
            return None

    def get_file_md5(self, file_list):
        """
        Get an array of file signatures
        :param file_list:
        :return: Array of file signatures.
        """
        with self.lock:
            resp = self._rpc('md5_files', (file_list, ))
            if resp and resp.ec == 200:
                return resp.result
            else:
                p('Error when retrieving md5sums %s' % str(resp))
            return None

    def update_files(self, file_list):
        """
        For each file in the file list, load it into memory, md5 it and
        send it to the client!
        :param file_list: List of files.
        :return: Boolean
        """
        pushed_files = []

        for f in file_list:
            fn = os.path.join(os.path.dirname(os.path.realpath(__file__)), f)
            md5_sum, data = file_md5_and_data(fn)
            pushed_files.append(dict(fn=f, md5=md5_sum, data=data))

        resp = self._rpc('update_files', (pushed_files, ))
        if resp and resp.ec == 200:
            return True

        p('Error when updating files! %s' % str(resp))
        return False

    def restart(self):
        """
        Restart the node!
        :return: None
        """
        # The node doesn't respond with a msg on a restart!
        self._rpc('restart')


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
        """
        Called to start the thread for main event loop.
        :return:
        """
        thread = threading.Thread(
            target=NodeManager.main_event_loop,
            name="Node Manager",
            args=(self, ))
        thread.start()

    def nodes(self):
        """
        Find which nodes are responsive.
        :return: List of responsive nodes.
        """
        rc = []
        with self.lock:
            for i in self.known_clients.values():
                # Make sure the node is responsive before adding it to the list
                # of nodes to run tests against
                if i.verify():
                    rc.append(i)

        return rc

    @staticmethod
    def _setup_listening(ip, port):
        bindsocket = socket.socket()
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bindsocket.bind((ip, port))
        bindsocket.listen(5)
        return bindsocket

    @staticmethod
    def _client_id(ip_address, arrays):
        return ip_address + '-' + '-'.join([i[0] for i in arrays])

    @staticmethod
    def main_event_loop(node_mgr):
        """
        Main event loop for node manager.
        :param node_mgr: Node manager object
        :return: None
        """

        # Setup the listening socket
        bindsocket = None
        try:
            bindsocket = NodeManager._setup_listening(node_mgr.ip,
                                                      node_mgr.port)
        except:
            p(str(traceback.format_exc()))
            p('Unable to setup listening socket (%s:%d), shutting down' %
              (node_mgr.ip, node_mgr.port))
            RUN.value = 0
            os.kill(os.getpid(), signal.SIGINT)

        while RUN.value:

            new_socket = None
            connection = None
            from_addr = None

            # noinspection PyBroadException
            try:
                ready = select.select([bindsocket], [], [bindsocket], 15)

                if len(ready[2]):
                    p("Error on listening socket, re-creating...")
                    _try_close(bindsocket)
                    bindsocket = NodeManager._setup_listening(
                        node_mgr.ip, node_mgr.port)
                else:
                    for r in ready[0]:
                        new_socket, from_addr = bindsocket.accept()

                        # Set a fairly short timeout, so badly behaving clients
                        # don't muck things up.
                        new_socket.settimeout(1)
                        connection = ssl.wrap_socket(
                            new_socket,
                            server_side=True,
                            certfile="server_cert.pem",
                            keyfile="server_key.pem",
                            ca_certs="client_cert.pem",
                            cert_reqs=ssl.CERT_REQUIRED)

                        with node_mgr.lock:
                            # If we already had this client, close previous and
                            # update with new.  We are expecting only one
                            # connection from any given unique IP.  We are
                            # doing this so if the connection fails we can
                            # re-associate to the same test node.  It is
                            # possible both ends are up and functional
                            # and the network goes down/up etc.
                            nc = Node(connection, from_addr)

                            arrays = sorted(nc.arrays())

                            # We have a well behaved client, increase timeouts
                            nc.increase_tmo()

                            msg = "Accepted a connection from %s: arrays= %s" \
                                    % (str(from_addr), str(arrays))

                            client_id = NodeManager._client_id(
                                from_addr[0], arrays)

                            if client_id in node_mgr.known_clients:
                                p("%s: previously known %s" % (msg, client_id))
                                node_mgr.known_clients[client_id].replace(nc)
                            else:
                                p("%s: new client connection %s" % (msg,
                                                                    client_id))
                                node_mgr.known_clients[client_id] = nc

                            NodeManager.check_for_updates(nc)

                    # If all the nodes are doing nothing, lets ping them to
                    # ensure they still are present and responding
                    with node_mgr.lock:
                        for i in node_mgr.known_clients.values():
                            i.verify()

            except KeyboardInterrupt:
                _try_close(bindsocket)
                sys.exit(1)
            except ssl.SSLError as ssle:
                # We get these errors when someone port scan and tries to
                # connect
                _try_close(new_socket)
                p("SSL error: Rejecting %s for %s" % (str(from_addr),
                                                      str(ssle)))
            except:
                p(str(traceback.format_exc()))
                _try_close(connection)
                _try_close(new_socket)

        p('Exiting node manager thread...')

    @staticmethod
    def check_for_updates(node):
        """
        Get the current signatures of the files we have and compare it to
        the ones on the node, if they don't match push them down and restart
        the client
        :param node: Client node of interest
        :return: None.
        """
        p('Checking for updates')
        local_signatures = []

        files = ['node.py', 'testlib.py', 'ci_unit_test.sh']

        for f in files:
            local_signatures.append(file_md5(f))

        remote_signatures = node.get_file_md5(files)
        if remote_signatures:
            if local_signatures != remote_signatures:
                p('Updating client!')
                for i, fn in enumerate(files):
                    if local_signatures[i] != remote_signatures[i]:
                        p('File %s local= %s remote= %s' %
                          (fn, local_signatures[i], remote_signatures[i]))

                if node.update_files(files):
                    remote_signatures = node.get_file_md5(files)
                    if local_signatures == remote_signatures:
                        node.restart()
                    else:
                        p("After updating files we have a md5 miss-match,"
                          " not restarting client!")
            else:
                p('Client is current!')
