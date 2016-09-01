#!/usr/bin/env python2
#
# Theory of operation
# 1. Read the config file getting
#    - Server and port to connect too
#    - What arrays are available to use
# 2. Connect to the server
# 3. Wait for a command request
# 4. If server connection goes away or haven't received ping, close connection
#    and try to periodically re-establish communication
#
# Command requests include:
# ping - check to see if the connection is working
# arrays - Return array information on what is available to test
# running - Return which arrays are currently running tests
# job_create - Submit a new test to run (Creates a new process)
# jobs - Return job state information on all submitted jobs
# job - Return job state information about a specific job
# job_delete - Delete the specific job request freeing resources
# job_completion - Retrieve the exit code and log for specified job
#
# Service which runs a test(s) on the same box as service
#
#  See: https://github.com/tasleson/lsm-ci/blob/master/LICENSE

import string
import random
import yaml
import os
import json
import sys
from subprocess import call
from multiprocessing import Process
import testlib
import time
import traceback


jobs = {}
config = {}


def _lcall(command, job_id):
    """
    Call an executable and return a tuple of exitcode, stdout&stderr
    """

    # Write output to a file so we can see what's going on while it's running
    f = '/tmp/%s.out' % job_id

    with open(f, 'w', buffering=1) as log:  # Max buffer 1 line (text mode)
        exit_value = call(command, stdout=log, stderr=log)
    return exit_value, f


def _file_name(job_id):
    base = '%s/%s' % (config["LOGDIR"], job_id)
    return base + ".out"


def _run_command(job_id, args):
    cmd = [config["PROGRAM"]]
    log_dir = config["LOGDIR"]

    cmd.extend(args)

    (ec, output_file) = _lcall(cmd, job_id)
    log = _file_name(job_id)

    # Read in output file in it's entirety
    with open(output_file, 'r') as o:
        out = o.read()

    # Delete file to prevent /tmp from filling up
    os.remove(output_file)

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
        config = yaml.load(array_data.read())

    # If the user didn't specify a full path in the configuration file we
    # expect it in the same directory as this file
    if config['PROGRAM'][0] != '/':
        config['PROGRAM'] = os.path.dirname(os.path.realpath(__file__)) + \
                            '/' + config['PROGRAM']

    # Lets make sure import external files/directories are present
    if not os.path.exists(config['PROGRAM']):
        print("config PROGRAM %s does not exist" % config['PROGRAM'])
        sys.exit(1)

    if not (os.path.exists(config['LOGDIR']) and
            os.path.isdir(config['LOGDIR']) and
            os.access(config['LOGDIR'], os.W_OK)):
        print("config LOGDIR not preset or not a "
              "directory %s or not writeable" % (config['LOGDIR']))
        sys.exit(1)


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


class Cmds(object):

    @staticmethod
    def ping():
        return "pong", 200, ""

    # Returns systems available for running tests
    @staticmethod
    def arrays():
        rc = [(x['ID'], x['PLUGIN']) for x in config['ARRAYS']]
        return rc, 200, ""

    # Returns all tests that are still running
    # returns array of dictionary
    # [ {"STATUS": ['RUNNING'|'SUCCESS'|'FAIL'}, "ID": <array id>,
    # "JOB_ID": [a-z]{32}, "PLUGIN":'lsm plugin'}, ... ]
    @staticmethod
    def running():
        rc = _only_running()

        return rc, 200, ""

    # Submit a new test to run
    # @param repo       The git repo to use
    # @param branch     The git branch
    # @param array_id   The test array ID
    # @returns http status code
    # 412 - Job already running on specified array
    # 400 - Input parameters are incorrect or missing
    # 201 - Test started
    @staticmethod
    def job_create(repo, branch, array_id):
        global jobs

        testlib.p("Running test for %s %s %s" % (repo, branch, array_id))

        if any([x for x in config['ARRAYS'] if x['ID'] == array_id]):

            # Add a check to make sure we aren't already _running_
            # a job for this array
            for k, v in jobs.items():
                if v['ID'] == array_id:
                    # Update status to make sure
                    _update_state(k)
                    if v['STATUS'] == 'RUNNING':
                        return "", 412, "Job already running on array"

            # Run the job
            # Build the arguments for the script
            uri = ""
            password = ""
            plug = ""

            for a in config['ARRAYS']:
                if a['ID'] == array_id:
                    uri = a['URI']
                    password = a['PASSWORD']
                    plug = a['PLUGIN']
                    break

            # When we add rpm builds we will need client to pass
            # which 'type' too
            incoming = ('git', repo, branch, uri, password)
            job_id = _rs(32)
            p = Process(target=_run_command, args=(job_id, incoming))
            p.name = "|".join(incoming)
            p.start()

            jobs[job_id] = dict(STATUS='RUNNING',
                                PROCESS=p,
                                ID=array_id,
                                PLUGIN=plug)
            return job_id, 201, ""
        else:
            return "", 400, "Invalid array specified!"

    # Returns all known jobs regardless of status
    # returns array of dictionaries
    @staticmethod
    def jobs():
        rc = []
        for k in jobs.keys():
            rc.append(_return_state(k))

        return rc, 200, ""

    # Get the status of the specified job
    @staticmethod
    def job(job_id):
        global jobs
        if job_id in jobs:
            return _return_state(job_id), 200, ""
        return "", 404, "Job not found!"

    # Get the exit code and log file for the specified job
    # @returns http status:
    # 200 on success
    # 400 if job is still running
    # 404 if job is not found
    # json payload { "EC": <exit code>, "OUTPUT": "std out + std error"}
    @staticmethod
    def job_completion(job_id):
        if job_id in jobs:
            j = jobs[job_id]
            log = _file_name(job_id)
            if j['STATUS'] != "RUNNING":
                with open(log, 'r') as foo:
                    result = yaml.safe_load(foo.read())
                return json.dumps(result), 200, ""
            else:
                return "", 400, "Job still running"
        else:
            return "", 404, "Job not found"

    # Delete a test that is no longer running, cleans up in memory hash and
    # removes log file from disk
    # @returns http status 200 on success, else 400 if job is still running
    # or 404 if job is not found
    @staticmethod
    def job_delete(job_id):
        global jobs
        if job_id in jobs:
            j = jobs[job_id]

            if j['STATUS'] != "RUNNING":
                del jobs[job_id]
                _remove_file(job_id)
                return "", 200, ""
            else:
                return "", 400, "Job still running"
        else:
            return "", 404, "Job not found"


def process_request(n, req):
    data = ""
    ec = 0
    error_msg = ""

    if hasattr(Cmds, req.method):
        if req.args and len(req.args):
            data, ec, error_msg = getattr(Cmds, req.method)(*req.args)
        else:
            data, ec, error_msg = getattr(Cmds, req.method)()
        n.return_response(testlib.Response(data, ec, error_msg))
    else:
        # Bounce this back to the requester
        n.return_response(testlib.Response("", 404, "Command not found!"))


if __name__ == "__main__":
    # Load the available test arrays from config file
    _load_config()

    # Connect to server
    while True:
        server = config['SERVER_IP']
        port = config['SERVER_PORT']

        testlib.p("Attempting connection to %s:%d" % (server, port))
        node = testlib.TestNode(server, port)

        if node.connect():
            # noinspection PyBroadException
            testlib.p("Connected!")
            try:
                while True:
                    request = node.wait_for_request()
                    process_request(node, request)
            except KeyboardInterrupt:
                node.disconnect()
                sys.exit(0)
            except Exception:
                testlib.p(str(traceback.format_exc()))
                pass

            # This probably won't do much as socket is quite likely toast
            node.disconnect()

        # If we get here we need to re-establish connection, make sure we don't
        # swamp the processor
        time.sleep(10)
