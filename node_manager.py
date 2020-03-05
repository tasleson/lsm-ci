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
try:
    # noinspection PyUnresolvedReferences,PyCompatibility
    import Queue
except ModuleNotFoundError:
    # noinspection PyUnresolvedReferences,PyCompatibility,PyPep8Naming
    import queue as Queue

import traceback
from testlib import p as _p
import re
from collections import deque
import json
import copy
import yaml


pp = pprint.PrettyPrinter(depth=4)

# What Host/IP & port to serve on
HOST = os.getenv('HOST', 'localhost')
PORT = os.getenv('PORT', '8080')

# What github username and token to update commit status on
USER = os.getenv('GIT_USER', '')
TOKEN = os.getenv('GIT_TOKEN', '')

# This is the API configured 'secret' for signing the payload from github ->
# this service.
GIT_SECRET = os.getenv('GIT_SECRET', '')

# Where to store the logs
ERROR_LOG_DIR = os.getenv('CI_LOG_DIR', '/tmp/ci_log')

# Where to find the logs, this is the url in the github status update when
# we have an error
CI_SERVICE_URL = os.getenv('CI_URL', 'http://%s:%s/log' % (HOST, PORT))

# The file with trusted repos in it
TRUSTED_REPO_FN = os.getenv('TRUSTED_REPOS', '')

# Full path to trusted file on repo itself
TRUSTED_REPO_REMOTE = os.getenv(
    'TRUSTED_REPOS_REMOTE',
    'https://raw.githubusercontent.com/' +
    'libstorage/libstoragemgmt/master/test/trusted.yaml')

# File name for log file which is retrievable by client
f_name = re.compile('[a-z]{32}\.html')

# We are storing a history of work, so that we can go back and re-run as needed
work_log = deque(maxlen=20)


node_mgr = testlib.NodeManager(HOST)
req_q = Queue.Queue()

test_count = 0

processing = None
processing_mutex = threading.Lock()


def _post_with_retries(url, data, auth):
    for i in range(0, 10):
        try:
            r = requests.post(url, auth=auth, json=data)
            return r
        except requests.ConnectionError as ce:
            _p("ConnectionError to (post) %s : message(%s)" %
                      (url, str(ce)))
            _p("Trying again in 1 second")
            time.sleep(1)


def _print_error(req, msg):
    formatted_json = pp.pformat(req.json())
    _p("%s status code = %d, \nJSON: \n%s\n" %
        (msg, req.status_code, formatted_json))


def _log_write(node, job_id):
    data = node.job_completion(job_id)

    if not data:
        # Node is down, not much to say here!
        data = "Unable to retrieve log, node not unavailable or hitting a bug!"

    with open(ERROR_LOG_DIR + '/' + job_id + '.html', 'w') as log_file:
        log_file.write(data.encode('utf-8'))


def _log_read(fn):
    data = ""
    # Ensure file name is matches are expectations
    if f_name.match(fn):
        # noinspection PyBroadException
        try:
            with open(ERROR_LOG_DIR + '/' + fn, 'r') as log_file:
                data = log_file.readlines()

            out = ""

            for l in data:
                if 'password' not in l and 'Password' not in l:
                    out += l
                else:
                    out += "**** Line omitted as it contains a password ****\n"
            return out
        except Exception:
            pass
    return None


# Note: A context is used to distinguish different origins of status
def _create_status(repo, sha1, state, desc, context, log_url=None):

    if '/' not in repo:
        raise Exception("Expecting repo to be in form user/repo %s" % repo)

    url = 'https://api.github.com/repos/%s/statuses/%s' % (repo, sha1)
    data = {'state': state, "description": desc, "context": context}

    if log_url:
        data["target_url"] = log_url

    r = _post_with_retries(url, data, (USER, TOKEN))
    if r.status_code == 201:
        _p('We updated status url=%s data=%s' % (str(url), str(data)))
    else:
        _print_error(r, "Unexpected error on setting status url=%s data=%s "
                     % (str(url), str(data)))


def trusted_repo(info):
    """
    Determine if we true a repo.

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
            trusted = yaml.load(result.text)
        else:
            if os.path.exists(TRUSTED_REPO_FN) and \
                    os.path.isfile(TRUSTED_REPO_FN):
                with open(TRUSTED_REPO_FN, 'r') as tdata:
                    trusted = yaml.load(tdata.read())

        if info['clone'] in trusted['REPOS']:
            _create_status(info["repo"], info['sha'], 'success',
                           'Repo trusted',
                           'CI permissions')
            return True
        else:
            _create_status(info["repo"], info['sha'], 'failure',
                           'Repo untrusted',
                           'CI permissions')
    except Exception as e:
        _p('Unable to retrieve trusted repo list! %s' % str(e))
        _create_status(info["repo"], info['sha'], 'failure',
                       'WL unavailable!',
                       'CI permissions')
    return False


def run_tests(info):
    """
    Run the tests.
    :param info: Information about what is to be tested
    :return: None
    """

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
            _create_status(info["repo"], info['sha'], "pending",
                           'Plugin = %s started @ %s' %
                           (a[1], datetime.datetime.fromtimestamp(
                               time.time()).strftime('%m/%d %H:%M:%S')),
                           a[0])

    _p('Starting the tests')

    # Start the tests
    for n in connected_nodes:
        arrays = n.arrays()
        for a in n.arrays():
            job = n.start_test(info['clone'], info['branch'], a[0])
            if job:
                _p("Test started for %s job = %s" % (a[0], job))
            else:
                _create_status(info["repo"], info['sha'], "failure",
                               'Plugin = ' + a[1] + 'failed to start', a[0])

    _p('Tests started')

    # Monitor and report status as they are completed
    all_done = False
    while not all_done:
        all_done = True

        for n in connected_nodes:
            # Get the jobs
            job_list = n.jobs()

            for r in job_list:
                job_id = r['JOB_ID']
                array_id = r['ID']
                status = r['STATUS']
                plugin = r['PLUGIN']

                if status == 'RUNNING':
                    all_done = False
                else:
                    if status == 'SUCCESS':
                        _create_status(info["repo"], info['sha'], 'success',
                                       'Plugin = ' + plugin, array_id)

                        info['status'] = 'SUCCESS'
                    else:
                        url = '%s/%s.html' % (CI_SERVICE_URL, job_id)
                        info['status'] = url
                        # Fetch the error log, log error data and status
                        _log_write(n, job_id)
                        _create_status(info["repo"], info['sha'], 'failure',
                                       'Plugin = ' + plugin, array_id, url)

                    # Delete the job if it's not running.
                    n.job_delete(job_id)

        time.sleep(5)

    work_log.append(info)

    _p('Test run completed')


# Probably a poor attempt at a constant time compare function, derived from the
# C source for hmac.compare_digest
def _tscmp(a, b):
    result = 0
    b_len = len(b)
    if len(a) != b_len:
        a = b
        result = 1

    for i in range(0, b_len):
        # noinspection PyUnresolvedReferences
        result |= ord(a[i]) ^ ord(b[i])

    return result == 0


# Verify the payload using our shared secret with github
def _verify_signature(payload_body, header_signature):
    # noinspection PyUnresolvedReferences
    h = hmac.new(GIT_SECRET, payload_body, hashlib.sha1)
    signature = 'sha1=' + h.hexdigest()
    try:
        # Python 2.7 and later have this which is suggested
        # noinspection PyUnresolvedReferences
        return hmac.compare_digest(signature, header_signature)
    except AttributeError:
        return _tscmp(signature, header_signature)


# Thread that runs taking work off of the request queue and processing it
def request_queue():
    """
    Loops processing items on the request queue.
    :return: None
    """
    global processing
    global processing_mutex

    while testlib.RUN.value:

        # noinspection PyBroadException
        try:
            info = req_q.get(True, 3)

            with processing_mutex:
                processing = info

            run_tests(info)

            with processing_mutex:
                processing = None
        except Queue.Empty:
            pass
        except Exception:
            st = traceback.format_exc()
            _p("request_queue: unexpected exception: %s" % st)

    _p('Exiting request_queue')


@route('/completed')
def completed_requests():
    """
    Handles the request for what has been completed.
    :return: JSON
    """
    rc = []
    c_r = reversed(list(work_log))

    response.content_type = 'application/json'

    for i in c_r:
        rc.append(i)

    return json.dumps(rc)


@route('/processing')
def processing_requests():
    """
    Handles the request for what is in processing.
    :return: JSON
    """
    global processing
    global processing_mutex
    rc = []

    response.content_type = 'application/json'

    with processing_mutex:
        if processing:
            rc.append(processing)

    return json.dumps(rc)


@route('/rerun/<test_id>')
def rerun_test(test_id):
    """
    Re-runs a test
    :param test_id:  Test id to re-run.
    :return: Appropriate http status code
    """
    global test_count

    tmp_id = 0

    # We are only expecting a number here
    try:
        tmp_id = int(test_id)
    except ValueError as ve:
        response.status = 404
        return

    submitted = False

    for i in list(work_log):
        # noinspection PyTypeChecker
        if int(i['test_run_id']) == int(test_id):
            # Try to make the test counts unique
            cpy = copy.deepcopy(i)

            _p('Re-running test: client IP %s: %s %s' %
                (request.remote_addr, str(test_id), str(cpy)))

            cpy['test_run_id'] = test_count
            test_count += 1
            req_q.put(cpy)
            response.status = 200
            submitted = True
            break

    if not submitted:
        response.status = 404
    return


# Return what clients we have connected to us
# Note: Don't leak too much information
@route('/nodes')
def nodes():
    """
    Returns connected clients.
    :return: JSON list of connected clients.
    """

    rc = []

    for n in node_mgr.nodes():
        rc.extend(n.arrays())

    response.content_type = 'application/json'
    return json.dumps(rc)


@route('/stats')
def stats():
    """
    Returns information on current request queue size.
    :return: JSON representation of queue size, eg. {"QUEUE_SIZE": 0}
    """
    response.content_type = 'application/json'
    return json.dumps(dict(QUEUE_SIZE=req_q.qsize()))


@route('/queue')
def queue():
    """
    Returns what's in the queue
    :return: Items in request Q as JSON.
    """
    rc = []
    response.content_type = 'application/json'

    wq = list(req_q.queue)
    for i in wq:
        rc.append(i)

    return json.dumps(rc)


@route('/log/<log_file>')
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
        return template('<pre>{{data}}</pre>', data=d)

    # Wrong or missing file or invalid file name
    response.status = 500
    return


@route('/event_handler', method='POST')
def e_handler():
    """
    Github calls this when we get a pull request
    :return: Http status code, 500 on error, else 200.
    """
    global test_count

    # Check secret before we do *anything*
    if not _verify_signature(request.body.read(),
                             request.headers['X-Hub-Signature']):
        response.status = 500
        return

    if request.headers['X-Github-Event'] == 'pull_request':
        repo = request.json["pull_request"]["base"]["repo"]["full_name"]
        clone = request.json["pull_request"]["head"]["repo"]["clone_url"]
        sha = request.json["pull_request"]['head']['sha']
        branch = request.json["pull_request"]['head']['ref']

        _p('Queuing unit tests for %s %s' % (clone, branch))

        info = dict(repo=repo, sha=sha, branch=branch, clone=clone,
                       test_run_id=test_count)

        # Lets immediately set something on the PR so that people looking at
        # the PR see that the service is aware of it.
        _create_status(info["repo"], info['sha'], 'pending',
                       'CI requested, #waiting = %d' % req_q.qsize(),
                       'CI permissions')
        req_q.put(info)

        test_count += 1
    else:
        _p("Got an unexpected header from github")
        for k, v in request.headers.items():
            _p('%s:%s' % (str(k), str(v)))
        pp.pprint(request.json)
        sys.stdout.flush()

    response.status = 200


if __name__ == "__main__":

    # Start up the node manager
    node_mgr.start()

    # Start up the thread to handle requests from github
    threading.Thread(target=request_queue, name="request_queue").start()

    # Start-up bottle for rest interface which github uses
    run(host=HOST, port=PORT)

    # ^C will exit bottle thread, we end up here so we will set our
    # global flag to exit too so our other threads will exit cleanly

    testlib.RUN.value = 0
