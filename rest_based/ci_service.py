#!/usr/bin/env python
"""
Service for github CI to talk too.  It also coordinates communication with all
the other nodes.

See: https://github.com/tasleson/lsm-ci/blob/master/LICENSE
"""
import pprint
import requests
from bottle import route, run, request, template
import os
from bottle import response
import time
from multiprocessing import Process
import hmac
import hashlib
import sys
import datetime

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


# Credentials to talk to test service
# TODO Place in yaml config file so that we can add services by editing text
#      file and adding entries
SNIA_USER = os.getenv('SNIA_USER', '')
SNIA_TOKEN = os.getenv('SNIA_TOKEN', '')
SNIA_URL = os.getenv('SNIA_URL', '')

# Where to store the logs
ERROR_LOG_DIR = os.getenv('CI_LOG_DIR', '/tmp/ci_log')

# Where to find the logs, this is the url in the github status update when
# we have an error
CI_SERVICE_URL = os.getenv('CI_URL', 'http://%s:%s/log' % (HOST, PORT))

# Global process list
processes = []


def _request_with_retries(url):
    for i in range(0, 10):
        try:
            r = requests.get(url, auth=(SNIA_USER, SNIA_TOKEN))
            return r
        except requests.ConnectionError as ce:
            _p("ConnectionError to (GET) %s : message(%s)" %
               (SNIA_URL, str(ce)))
            _p("Trying again in 1 second")
            time.sleep(1)


def _post_with_retries(url, data, auth):
    for i in range(0, 10):
        try:
            r = requests.post(url, auth=auth, json=data)
            return r
        except requests.ConnectionError as ce:
            _p("ConnectionError to (post) %s : message(%s)" %
               (SNIA_URL, str(ce)))
            _p("Trying again in 1 second")
            time.sleep(1)


def _arrays_available():
    r = _request_with_retries(SNIA_URL + '/' + 'arrays')
    if r.status_code == 200:
        return r.json()
    return []


def _arrays_running():
    r = _request_with_retries(SNIA_URL + '/' + 'running')
    if r.status_code == 200:
        return r.json()
    return []


def _print_error(req, msg):
    _p("%s status code = %d" % (msg, req.status_code))
    pp.pprint(req.json())
    sys.stdout.flush()


def _array_start(clone_url, branch, array_id):
    data = {"REPO": clone_url, "BRANCH": branch, "ID": array_id}
    r = _post_with_retries(SNIA_URL + '/' + 'test', data,
                           (SNIA_USER, SNIA_TOKEN))

    if r.status_code != 201:
        _print_error(r, 'Unexpected error on starting test')
        return None
    else:
        result = r.json()
        return result['JOB_ID']


def _log_write(job_id):
    url = "%s/log/%s" % (SNIA_URL, job_id)
    r = _request_with_retries(url)
    if r.status_code == 200:
        data = r.json()['OUTPUT']
        with open(ERROR_LOG_DIR + '/' + job_id + '.html', 'w') as log_file:
            log_file.write(data)


def _log_read(fn):
    data = ""
    # TODO Check to make sure file name is [a-z].html only, or do we need too?
    with open(ERROR_LOG_DIR + '/' + fn, 'r') as log_file:
        data = log_file.readlines()

    out = ""

    # Make sure we don't expose plain word password in the log files.
    for line in data:
        if 'password' not in line and 'Password' not in line:
            out += line
        else:
            out += "**** Line omitted as it contains a password ****\n"
    return out


def _jobs():
    r = _request_with_retries(SNIA_URL + '/' + 'test')
    if r.status_code == 200:
        return r.json()
    return []


def _job_delete(job_id):
    url = "%s/test/%s" % (SNIA_URL, job_id)
    r = requests.delete(url, auth=(SNIA_USER, SNIA_TOKEN))
    if r.status_code != 200:
        _print_error(r, "Unexpected error on delete ")


# Note: A context is used to distinguish different origins of status
def _create_status(repo, sha1, state, desc, context, log_url=None):
    if '/' not in repo:
        raise Exception("Expecting repo to be in form user/repo %s" % repo)

    url = 'https://api.github.com/repos/%s/statuses/%s' % (repo, sha1)
    data = {'state': state, "description": desc, "context": context}

    if log_url:
        data["target_url"] = log_url

    r = _post_with_retries(url, data, (HOST, TOKEN))
    if r.status_code == 201:
        _p('We updated status %s' % str(data))
    else:
        _print_error(r, "Unexpected error on setting status ")


def _run_tests(info):
    jobs = {}
    _p('Task running! %d' % os.getpid())

    # Connect to the various lab(s) and kick off builds for each of the
    # available plugins
    arrays = _arrays_available()

    # Set all the status
    for a in arrays:
        _create_status(info["repo"], info['sha'], "pending",
                       'Plugin = %s started @ %s' %
                       (a[1], datetime.datetime.fromtimestamp(
                           time.time()).strftime('%m/%d %H:%M:%S')),
                       a[0])

    # Wait until all the arrays are free
    # TODO re-work this with some type of scheduler
    while True:
        in_use = _arrays_running()
        if len(in_use) == 0:
            break
        time.sleep(30)

    _p('Starting the tests!')

    # Start the tests
    for a in arrays:
        job = _array_start(info['clone'], info['branch'], a[0])
        if job:
            jobs[job] = (a[0], a[1])
        else:
            _create_status(info["repo"], info['sha'], "failure",
                           'Plugin = ' + a[1] + 'failed to start', a[0])

    _p('Tests started')

    # Loop until they are all done
    running = _arrays_running()
    while len(running) > 0:
        time.sleep(15)
        running = _arrays_running()

    # Report status on each of them
    job_list = _jobs()

    _p('Tests done, jobs = %s' % str(job_list))

    for r in job_list:
        job_id = r['JOB_ID']
        array_id = r['ID']
        status = r['STATUS']
        plugin = r['PLUGIN']

        if status == 'SUCCESS':
            _create_status(info["repo"], info['sha'], 'success',
                           'Plugin = ' + plugin, array_id)
        else:
            # Fetch the error log
            _log_write(job_id)
            _create_status(info["repo"], info['sha'], 'failure',
                           'Plugin = ' + plugin, array_id,
                           '%s/%s.html' % (CI_SERVICE_URL, job_id))

        # Delete the jobs
        _job_delete(job_id)
    _p('Task completed!')
    sys.exit(0)


@route('/log/<log_file>')
def fetch(log_file):
    """
    Method which takes a given log file and reads it up to return.
    :param log_file: Log file to fetch
    :return: Data surrounded with <pre></pre> tags
    """
    d = _log_read(log_file)
    if len(d) == 0:
        d = "Nothing to see here..."
    return template('<pre>{{data}}</pre>', data=d)


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


def _clean_process_list():
    global processes
    to_remove = []

    # House keeping
    for p in processes:
        p.join(0)
        if not p.is_alive():
            _p('%s exited with %s ' % (p.name, str(p.exitcode)))
            to_remove.append(p)

    for r in to_remove:
        processes.remove(r)


def _p(msg):
    ts = datetime.datetime.fromtimestamp(
        time.time()).strftime('%Y-%m-%d %H:%M:%S')
    print("%s:%d:%s" % (ts, os.getpid(), msg))
    sys.stdout.flush()


# Github calls this when we get a pull request
@route('/event_handler', method='POST')
def e_handler():
    """
    This is the handler that gets called when github has a new PR for us to
    do something upon.
    :return: http status code 200 on success, else 500.
    """
    global processes

    # Check secret before we do anything
    if not _verify_signature(request.body.read(),
                             request.headers['X-Hub-Signature']):
        response.status = 500
        return

    # To keep things simple, we will do process clean-up when requests come
    # in, side effect is we will always have at least 1 zombie process hanging
    # around.  We could start another process to 'clean' up, but then we would
    # need to add locking to prevent concurrent access to processes list.  If
    # bottle had a timer we could use we could periodically run a task to
    # clean up.
    _clean_process_list()

    if request.headers['X-Github-Event'] == 'pull_request':
        repo = request.json["pull_request"]["base"]["repo"]["full_name"]
        clone = request.json["pull_request"]["head"]["repo"]["clone_url"]
        sha = request.json["pull_request"]['head']['sha']
        branch = request.json["pull_request"]['head']['ref']

        _p('Running unit tests for %s %s' % (clone, branch))

        info = dict(repo=repo, sha=sha, branch=branch, clone=clone)

        # Lets update the status
        p = Process(target=_run_tests, args=(info,))
        p.start()
        processes.append(p)

    else:
        _p("Got an unexpected header from github")
        for k, v in request.headers.items():
            _p('%s:%s' % (str(k), str(v)))
        pp.pprint(request.json)
        sys.stdout.flush()

    response.status = 200

if __name__ == "__main__":
    run(host=HOST, port=PORT)
