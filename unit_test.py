#!/usr/bin/env python
#
# Service which runs a test(s) on the same box as service
#
#  See: https://github.com/tasleson/lsm-ci/blob/master/LICENSE

from bottle import route, run, request, auth_basic
import string
import random
import yaml
import os
from bottle import response
import json
import sys
from subprocess import Popen, PIPE, STDOUT
from multiprocessing import Process


jobs = {}
config = {}


def _check(user, pw):
    if config["USER"] == user and config["PASSWORD"] == pw:
        return True
    return False


def _call(command):
    """
    Call an executable and return a tuple of exitcode, stdout&stderr
    """
    process = Popen(command, stdout=PIPE, stderr=STDOUT)
    out = process.communicate()
    return process.returncode, out[0]


def _file_name(job_id):
    base = '%s/%s' % (config["LOGDIR"], job_id)
    return base + ".out"


def _run_command(job_id, args):
    cmd = [config["PROGRAM"]]
    log_dir = config["LOGDIR"]

    cmd.extend(args)

    (ec, out) = _call(cmd)
    log = _file_name(job_id)

    with open(log, 'w') as error_file:
        error_file.write(yaml.dump(dict(EC=str(ec), OUTPUT=out)))
        error_file.flush()

    # This is a separate process, lets exit with the same exit code as cmd
    sys.exit(ec)


def _rs(l):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(l))


def _load_config():
    global config
    cfg = os.path.dirname(os.path.realpath(__file__)) + "/" + "config.yaml"
    with open(cfg, 'r') as array_data:
        config = yaml.safe_load(array_data.read())


def _remove_file(job_id):
    try:
        os.remove(_file_name(job_id))
    except IOError as ioe:
        pass


def _update_state(job_id):
    global jobs
    job = jobs[job_id]

    # See if the process has ended
    p = job['PROCESS']
    p.join(0)
    if not p.is_alive():
        print '%s exited with %s ' % (p.name, str(p.exitcode))
        sys.stdout.flush()

        if p.exitcode == 0:
            job['STATUS'] = 'SUCCESS'
        else:
            job['STATUS'] = 'FAIL'


def _return_state(job_id, only_running=False):
    _update_state(job_id)
    job = jobs[job_id]

    if not only_running or (only_running and job["STATUS"] == 'RUNNING'):
        return {"STATUS": job["STATUS"], "ID": job['ID'],
                "JOB_ID": job_id, "PLUGIN": job['PLUGIN']}
    return None


# State for tests are are currently running
# @returns JSON array with the following:
#
def _only_running():
    rc = []
    for k in jobs.keys():
        s = _return_state(k, True)
        if s:
            rc.append(s)
    return rc


# Returns systems available for running tests
@route('/arrays')
@auth_basic(_check)
def arrays():
    response.content_type = 'application/json'
    return json.dumps([(x['ID'], x['PLUGIN']) for x in config['ARRAYS']])


# Returns all tests that are still running
# returns JSON array
# [ {"STATUS": ['RUNNING'|'SUCCESS'|'FAIL'}, "ID": <array id>,
# "JOB_ID": [a-z]{32}, "PLUGIN":'lsm plugin'}, ... ]
@route('/running')
@auth_basic(_check)
def running():
    rc = _only_running()
    response.content_type = 'application/json'
    return json.dumps(rc)


# All tests that have been submitted in the JSON form:
# returns JSON array
# [ {"STATUS": ['RUNNING'|'SUCCESS'|'FAIL'}, "ID": <array id>,
# "JOB_ID": [a-z]{32}, "PLUGIN":'lsm plugin'}, ... ]
@route('/test')
@auth_basic(_check)
def all_tests():
    rc = []
    for k in jobs.keys():
        rc.append(_return_state(k))
    response.content_type = 'application/json'
    return json.dumps(rc)


# Submit a new test to run, takes a JSON request body that has the following
# key-values: REPO, BRANCH, ID(array id), returns JSON {"JOB_ID":"[a-z][32]"}
# Returns http status code
# 412 - Job already running on specified array
# 400 - Input parameters are incorrect or missing
# 201 - Test started
@route('/test', method='POST')
@auth_basic(_check)
def test():
    global jobs
    req = request.json

    if req and 'REPO' in req and 'BRANCH' in req and 'ID' in req and \
            any([x for x in config['ARRAYS'] if x['ID'] == req['ID']]):

        # Add a check to make sure we aren't already _running_ a job for this
        # array
        for k, v in jobs.items():
            if v['ID'] == req['ID']:
                # Update status to make sure
                _update_state(k)
                if v['STATUS'] == 'RUNNING':
                    response.status = 412   # Precondition fail
                    return

        # Run the job
        # Build the arguments for the script
        uri = ""
        password = ""
        plug = ""

        for a in config['ARRAYS']:
            if a['ID'] == req['ID']:
                uri = a['URI']
                password = a['PASSWORD']
                plug = a['PLUGIN']
                break

        # When we add rpm builds we will need client to pass which 'type' too
        incoming = ('git', req['REPO'], req['BRANCH'], uri, password)
        job_id = _rs(32)
        p = Process(target=_run_command, args=(job_id, incoming))
        p.name = "|".join(incoming)
        p.start()

        jobs[job_id] = dict(STATUS='RUNNING',
                            PROCESS=p,
                            ID=req['ID'],
                            PLUGIN=plug)
        response.status = 201
        return {"JOB_ID": job_id}
    else:
        response.status = 400


# Get the status of the specified job
@route('/test/<job_id>', method='GET')
@auth_basic(_check)
def status(job_id):
    global jobs
    if job_id in jobs:
        return _return_state(job_id)
    response.status = 404


# Delete a test that is no longer running, cleans up in memory hash and removes
# log file from disk
# @returns http status 200 on success, else 400 if job is still running or 404
# if job is not found
@route('/test/<job_id>', method='DELETE')
@auth_basic(_check)
def test_del(job_id):
    global jobs
    if job_id in jobs:
        j = jobs[job_id]

        if j['STATUS'] != "RUNNING":
            del jobs[job_id]
            _remove_file(job_id)
        else:
            response.status = 400
    else:
        response.status = 404


# Get the exit code and log file for the specified job
# @returns http status:
# 200 on success
# 400 if job is still running
# 404 if job is not found
# json payload { "EC": <exit code>, "OUTPUT": "std out + std error"}
@route('/log/<job_id>')
@auth_basic(_check)
def cat_it(job_id):
    if job_id in jobs:
        j = jobs[job_id]
        log = _file_name(job_id)
        if j['STATUS'] != "RUNNING":
            with open(log, 'r') as foo:
                result = yaml.safe_load(foo.read())
            return json.dumps(result)
        else:
            response.status = 400
    else:
        response.status = 404


if __name__ == "__main__":
    # Load the available test arrays from config file
    _load_config()
    run(host='localhost', port=8080)
