#!/usr/bin/python3
"""
Service for github CI to talk too
See: https://github.com/tasleson/lsm-ci/blob/master/LICENSE
"""
import pprint
import requests
from bottle import route, run, request, template
import os
from bottle import response
import time
import threading
import hmac
import hashlib
import sys
import datetime
import testlib
import errno
import queue as Queue

import traceback
from testlib import p as _p
import re
from collections import deque
import json
import yaml

pp = pprint.PrettyPrinter(depth=4)

# Development mode: set LSM_CI_DEV_MODE=1 to bypass signature verification
# and disable client updates. Useful for rapid development/testing. NEVER use in production!
DEV_MODE = os.getenv("LSM_CI_DEV_MODE", "") == "1"


class ThreadSafeWorkLog:
    """
    Thread-safe wrapper for the work log deque.
    All operations are protected by a lock.
    """

    def __init__(self, maxlen=20):
        self._deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def append(self, item):
        """Add an item to the work log."""
        with self._lock:
            self._deque.append(item)

    def get_all(self):
        """Get a snapshot of all items (newest to oldest)."""
        with self._lock:
            return list(reversed(self._deque))

    def find_by_test_id(self, test_id):
        """
        Find a work item by test_run_id.
        Returns a copy of the item or None.
        """
        with self._lock:
            for item in self._deque:
                if int(item["test_run_id"]) == int(test_id):
                    return dict(item)  # Return a copy
            return None


class AtomicCounter:
    """
    Thread-safe counter with atomic increment.
    """

    def __init__(self, initial=0):
        self._value = initial
        self._lock = threading.Lock()

    def increment(self):
        """Atomically increment and return the NEW value."""
        with self._lock:
            self._value += 1
            return self._value

    def get(self):
        """Get current value."""
        with self._lock:
            return self._value


# What Host/IP & port to serve on
HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "8080")

# What github username and token to update commit status on
USER = os.getenv("GIT_USER", "")
TOKEN = os.getenv("GIT_TOKEN", "")

# This is the API configured 'secret' for signing the payload from github ->
# this service.
GIT_SECRET = os.getenv("GIT_SECRET", "")

# Where to store the logs
ERROR_LOG_DIR = os.getenv("CI_LOG_DIR", "/tmp/ci_log")

# Where to find the logs, this is the url in the github status update when
# we have an error
CI_SERVICE_URL = os.getenv("CI_URL", f"http://{HOST}:{PORT}/log")

# The file with trusted repos in it
TRUSTED_REPO_FN = os.getenv("TRUSTED_REPOS", "")

# Full path to trusted file on repo itself
TRUSTED_REPO_REMOTE = os.getenv(
    "TRUSTED_REPOS_REMOTE",
    "https://raw.githubusercontent.com/" +
    "libstorage/libstoragemgmt/master/test/trusted.yaml",
)

# When we test locally we don't want to try and set status on github.
POST_STATUS = bool(os.getenv("POST_STATUS", ""))

# File name for log file which is retrievable by client
f_name = re.compile("[a-z]{32}.html")

# We are storing a history of work, so that we can go back and re-run as needed
work_log = ThreadSafeWorkLog(maxlen=20)

node_mgr = testlib.NodeManager(HOST)
req_q = Queue.Queue()
req_q_lock = threading.Lock()  # Lock for safe access to req_q.queue internals

test_count = AtomicCounter()

processing = None
processing_mutex = threading.Lock()


def _post_with_retries(url, data, auth):
    for i in range(0, 10):
        try:
            r = requests.post(url, auth=auth, json=data)
            return r
        except requests.ConnectionError as ce:
            _p(f"ConnectionError to (post) {url} : message({ce})")
            _p("Trying again in 1 second")
            time.sleep(1)


def _print_error(req, msg):
    formatted_json = pp.pformat(req.json())
    _p(f"{msg} status code = {req.status_code}, \nJSON: \n{formatted_json}\n")


def _log_write(node, job_id):
    data = node.job_completion(job_id)

    if not data:
        # Node is down, not much to say here!
        data = "Unable to retrieve log, node not unavailable or hitting a bug!"

    with open(ERROR_LOG_DIR + "/" + job_id + ".html", "w") as log_file:
        log_file.write(data)


def _log_read(fn):
    data = ""
    # Ensure file name is matches are expectations
    if f_name.match(fn):
        # noinspection PyBroadException
        try:
            with open(ERROR_LOG_DIR + "/" + fn, "r") as log_file:
                data = log_file.readlines()

            out = ""

            for line in data:
                if "password" not in line and "Password" not in line:
                    out += line
                else:
                    out += "**** Line omitted as it contains a password ****\n"
            return out
        except Exception as e:
            _p(f"_log_read error: {e}")
            pass
    return None


# Note: A context is used to distinguish different origins of status
def _create_status(repo, sha1, state, desc, context, log_url=None):

    if "/" not in repo:
        raise Exception(f"Expecting repo to be in form user/repo {repo}")

    url = f"https://api.github.com/repos/{repo}/statuses/{sha1}"
    data = {"state": state, "description": desc, "context": context}

    if log_url:
        data["target_url"] = log_url

    if POST_STATUS:
        r = _post_with_retries(url, data, (USER, TOKEN))
        if r.status_code == 201:
            _p(f"We updated status url={url} data={data}")
        else:
            _print_error(
                r,
                f"Unexpected error on setting status url={url} data={data} ",
            )
    else:
        _p(f"NOT POSTED: updated status url={url} data={data}")


def trusted_repo(info):
    """
    Determine if we trust a repo.

    We are opening the file each time, so we can update it without restarting
    # the service.
    :param info:  Information about what is to be tested
    :return: True/False
    """

    trusted = {}

    # Lets fetch the file from the master repo if it exists, otherwise we will
    # use our local copy.
    try:
        result = requests.get(TRUSTED_REPO_REMOTE)

        if result.status_code == 200:
            _p("Using github repo trusted file.")
            trusted = yaml.safe_load(result.text)
        else:
            if os.path.exists(TRUSTED_REPO_FN) and os.path.isfile(
                    TRUSTED_REPO_FN):
                with open(TRUSTED_REPO_FN, "r") as tdata:
                    trusted = yaml.safe_load(tdata.read())

        if info["clone"] in trusted["REPOS"]:
            _create_status(
                info["repo"],
                info["sha"],
                "success",
                "Repo trusted",
                "CI permissions",
            )
            return True
        else:
            _create_status(
                info["repo"],
                info["sha"],
                "failure",
                "Repo untrusted",
                "CI permissions",
            )
    except Exception as e:
        _p(f"Unable to retrieve trusted repo list! {e}")
        _create_status(
            info["repo"],
            info["sha"],
            "failure",
            "WL unavailable!",
            "CI permissions",
        )
    return False


def log_dir_create():
    """
    Check for the existence for logging dir, create if needed.
    :return:
    """
    try:
        os.makedirs(ERROR_LOG_DIR)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def run_tests(info):
    """
    Run the tests.
    :param info: Information about what is to be tested
    :return: None
    """

    # Lets make sure the logging directory exists
    log_dir_create()

    # As nodes can potentially come/go with errors we will get a list of what
    # we started with and will try to utilize them and only them for the
    # duration of the test
    connected_nodes = node_mgr.nodes()

    # Lets do a whitelist check, to ensure only those users who we trust are
    # going to get automated unit tests run.
    if not trusted_repo(info):
        return

    _p("Setting status @ github to pending")
    for n in connected_nodes:
        # Add status updates to github for all the arrays we will be testing
        # against
        arrays = n.arrays()

        # Set all the status
        for a in arrays:
            _create_status(
                info["repo"],
                info["sha"],
                "pending",
                f"Plugin = {a[1]} started @ {datetime.datetime.fromtimestamp(time.time()).strftime('%m/%d %H:%M:%S')}",
                a[0],
            )

    _p("Starting the tests")

    # Start the tests
    for n in connected_nodes:
        arrays = n.arrays()
        for a in n.arrays():
            job = n.start_test(info["clone"], info["branch"], a[0])
            if job:
                _p(f"Test started for {a[0]} job = {job}")
            else:
                _create_status(
                    info["repo"],
                    info["sha"],
                    "failure",
                    "Plugin = " + a[1] + "failed to start",
                    a[0],
                )

    _p("Tests started")

    # Monitor and report status as they are completed
    all_done = False
    while not all_done:
        all_done = True

        for n in connected_nodes:
            # Get the jobs
            job_list = n.jobs()

            for r in job_list:
                job_id = r["JOB_ID"]
                array_id = r["ID"]
                status = r["STATUS"]
                plugin = r["PLUGIN"]

                if status == "RUNNING":
                    all_done = False
                else:
                    if status == "SUCCESS":
                        _create_status(
                            info["repo"],
                            info["sha"],
                            "success",
                            "Plugin = " + plugin,
                            array_id,
                        )

                        info["status"] = "SUCCESS"
                    else:
                        url = f"{CI_SERVICE_URL}/{job_id}.html"
                        info["status"] = url
                        # Fetch the error log, log error data and status
                        _log_write(n, job_id)
                        _create_status(
                            info["repo"],
                            info["sha"],
                            "failure",
                            "Plugin = " + plugin,
                            array_id,
                            url,
                        )

                    # Delete the job if it's not running.
                    n.job_delete(job_id)

        time.sleep(5)

    work_log.append(info)

    _p("Test run completed")


# Verify the payload using our shared secret with github
def _verify_signature(payload_body, header_signature):
    # noinspection PyUnresolvedReferences
    h = hmac.new(GIT_SECRET.encode("utf-8"), payload_body, hashlib.sha1)
    signature = "sha1=" + h.hexdigest()
    return hmac.compare_digest(signature, header_signature)


# Thread that runs taking work off of the request queue and processing it
def request_queue():
    """
    Loops processing items on the request queue.
    :return: None
    """
    global processing
    global processing_mutex

    # Make sure logging directory exists
    log_dir_create()

    while testlib.RUN.value:

        # noinspection PyBroadException
        try:
            info = req_q.get(True, testlib.POLL_TIMEOUT)

            with processing_mutex:
                processing = info

            run_tests(info)

            with processing_mutex:
                processing = None
        except Queue.Empty:
            pass
        except Exception:
            st = traceback.format_exc()
            _p(f"request_queue: unexpected exception: {st}")

    _p("Exiting request_queue")


@route("/completed")
def completed_requests():
    """
    Handles the request for what has been completed.
    :return: JSON
    """
    response.content_type = "application/json"
    return json.dumps(work_log.get_all())


@route("/processing")
def processing_requests():
    """
    Handles the request for what is in processing.
    :return: JSON
    """
    global processing
    global processing_mutex
    rc = []

    response.content_type = "application/json"

    with processing_mutex:
        if processing:
            rc.append(processing)

    return json.dumps(rc)


@route("/rerun/<auth_param>")
def rerun_test(auth_param):
    """
    Re-runs a test with SHA256 authentication
    :param auth_param: Format: sha256=<hex>:<test_id>
                       where <hex> is SHA256(GIT_SECRET + test_id)
    :return: Appropriate http status code
    """
    # Parse the auth_param format: sha256=<hex>:<test_id>
    try:
        if not auth_param.startswith("sha256="):
            response.status = 400
            return "Invalid format: must start with 'sha256='"

        # Remove "sha256=" prefix
        param_data = auth_param[7:]  # len("sha256=") == 7

        # Split on the colon to get hash and test_id
        parts = param_data.split(":", 1)
        if len(parts) != 2:
            response.status = 400
            return "Invalid format: expected sha256=<hex>:<test_id>"

        provided_hash, test_id_str = parts

        # Validate test_id is an integer
        test_id = int(test_id_str)

        # Compute expected hash: SHA256(GIT_SECRET + test_id)
        message = GIT_SECRET + test_id_str
        expected_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()

        # Compare hashes using constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(provided_hash.lower(),
                                   expected_hash.lower()):
            response.status = 403
            _p(f"Invalid SHA256 authentication for test_id {test_id} from {request.remote_addr}"
               )
            return "Authentication failed"

    except ValueError:
        response.status = 400
        return "Invalid test_id: must be an integer"
    except Exception as e:
        response.status = 400
        return f"Error parsing auth parameter: {str(e)}"

    # Thread-safe lookup in work_log
    item = work_log.find_by_test_id(test_id)

    if item:
        _p(f"Re-running test: client IP {request.remote_addr}: {test_id} {item}"
           )

        # Atomically get new test_run_id
        item["test_run_id"] = test_count.increment()
        req_q.put(item)
        response.status = 200
        return "Test queued for rerun"
    else:
        response.status = 404
        return "Test not found"


# Return what clients we have connected to us
# Note: Don't leak too much information
@route("/nodes")
def nodes():
    """
    Returns connected clients.
    :return: JSON list of connected clients.
    """

    rc = []

    for n in node_mgr.nodes():
        rc.extend(n.arrays())

    response.content_type = "application/json"
    return json.dumps(rc)


@route("/stats")
def stats():
    """
    Returns information on current request queue size.
    :return: JSON representation of queue size, eg. {"QUEUE_SIZE": 0}
    """
    response.content_type = "application/json"
    return json.dumps(dict(QUEUE_SIZE=req_q.qsize()))


@route("/queue")
def queue():
    """
    Returns what's in the queue
    :return: Items in request Q as JSON.
    """
    rc = []
    response.content_type = "application/json"

    # Thread-safe access to queue internals
    # Hold lock while accessing req_q.queue to prevent race conditions
    with req_q_lock:
        # Access the internal deque under lock
        wq = list(req_q.queue)
        for i in wq:
            rc.append(i)

    return json.dumps(rc)


@route("/log/<log_file>")
def fetch(log_file):
    """
    A URL is given back to github on error, clients web browsers will call this
    link to get the log file.
    :param log_file: Log file to retrieve.
    :return:
    """
    d = _log_read(log_file)

    if d:
        if len(d) == 0:
            d = "Nothing to see here..."
        return template("<pre>{{data}}</pre>", data=d)

    # Wrong or missing file or invalid file name
    response.status = 500
    return


@route("/event_handler", method="POST")
def e_handler():
    """
    Github calls this when we get a pull request
    :return: Http status code, 500 on error, else 200.
    """
    # Check secret before we do *anything*
    if not _verify_signature(request.body.read(),
                             request.headers["X-Hub-Signature"]):
        response.status = 500
        return

    if request.headers["X-Github-Event"] == "pull_request":
        repo = request.json["pull_request"]["base"]["repo"]["full_name"]
        clone = request.json["pull_request"]["head"]["repo"]["clone_url"]
        sha = request.json["pull_request"]["head"]["sha"]
        branch = request.json["pull_request"]["head"]["ref"]

        _p(f"Queuing unit tests for {clone} {branch}")

        # Atomically get and increment test count
        current_test_id = test_count.increment()

        info = dict(
            repo=repo,
            sha=sha,
            branch=branch,
            clone=clone,
            test_run_id=current_test_id,
        )

        # Lets immediately set something on the PR so that people looking at
        # the PR see that the service is aware of it.
        _create_status(
            info["repo"],
            info["sha"],
            "pending",
            f"CI requested, #waiting = {req_q.qsize()}",
            "CI permissions",
        )
        req_q.put(info)
    else:
        _p("Got an unexpected header from github")
        for k, v in request.headers.items():
            _p(f"{k}:{v}")
        pp.pprint(request.json)
        sys.stdout.flush()

    response.status = 200


def verify_startup_signatures():
    """
    Verify that signatures.json exists and files match their signatures.

    The server should verify it has valid signed files before pushing
    updates to clients. This prevents pushing unsigned or tampered files.

    Returns: (success, error_message)
    """
    # Allow bypassing in development mode
    if DEV_MODE:
        testlib.p("⚠ DEV MODE: Skipping server startup signature verification")
        testlib.p("  Client updates will be disabled")
        return True, ""

    testlib.p("Verifying file signatures on server startup...")

    # Check if signatures.json exists
    sig_file = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                            'signatures.json')
    if not os.path.exists(sig_file):
        return False, "signatures.json not found - cannot push updates to clients"

    try:
        with open(sig_file) as f:
            signatures = json.load(f)
    except Exception as e:
        return False, f"Failed to load signatures.json: {e}"

    # Verify the files we'll be pushing match their signatures
    files_to_check = ['node.py', 'testlib.py', 'ci_unit_test.sh']

    for filename in files_to_check:
        if filename not in signatures:
            return False, f"No signature for {filename} in signatures.json"

        sig_data = signatures[filename]
        expected_hash = sig_data.get('sha256')

        if not expected_hash:
            return False, f"Invalid signature data for {filename}"

        # Calculate actual hash
        file_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 filename)
        try:
            actual_hash = testlib.file_sha256(file_path)
        except Exception as e:
            return False, f"Failed to hash {filename}: {e}"

        # Verify hash matches
        if actual_hash != expected_hash:
            return False, f"File {filename} has been modified since signing - re-sign before starting!"

    testlib.p("✓ Server startup signature verification passed")
    testlib.p(
        "  All files match their signatures and are ready to push to clients")
    return True, ""


if __name__ == "__main__":

    # Verify signatures before starting
    success, error_msg = verify_startup_signatures()
    if not success:
        testlib.p(f"✗ SIGNATURE VERIFICATION FAILED!")
        testlib.p(f"  {error_msg}")
        testlib.p("")
        testlib.p("The server will NOT push unsigned files to clients.")
        testlib.p("Please re-sign files before starting:")
        testlib.p("  python3 tools/sign_files.py --key <your-signing-key>")
        testlib.p("")
        sys.exit(1)

    # Start up the node manager
    node_mgr.start()

    # Start up the thread to handle requests from github
    threading.Thread(target=request_queue, name="request_queue").start()

    # Start-up bottle for rest interface which github uses
    run(host=HOST, port=PORT)

    # ^C will exit bottle thread, we end up here so we will set our
    # global flag to exit too so our other threads will exit cleanly

    testlib.RUN.value = 0
