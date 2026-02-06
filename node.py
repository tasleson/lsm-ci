#!/usr/bin/env python3
"""
WARNING!  This file is auto updated from the node manager.  Any changes will
be lost when the client disconnects and reconnects.

This file is compatible with python3 only.

Theory of operation
1. Read the config file getting
   - Server and port to connect too
   - What arrays are available to use
2. Connect to the server
3. Wait for a command request
4. If server connection goes away or haven't received ping, close connection
   and try to periodically re-establish communication
Command requests include:
ping - check to see if the connection is working
arrays - Return array information on what is available to test
running - Return which arrays are currently running tests
job_create - Submit a new test to run (Creates a new process)
jobs - Return job state information on all submitted jobs
job - Return job state information about a specific job
job_delete - Delete the specific job request freeing resources
job_completion - Retrieve the exit code and log for specified job
Service which runs a test(s) on the same box as service
 See: https://github.com/tasleson/lsm-ci/blob/master/LICENSE
"""

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
import tempfile
import shutil
import threading
import errno


class ThreadSafeJobManager:
    """
    Thread-safe wrapper for the jobs dictionary.
    All operations are protected by a reentrant lock.
    """

    def __init__(self):
        self._jobs = {}
        self._lock = threading.RLock()  # Reentrant lock

    def create_job(self, job_id, job_data):
        """
        Atomically create a new job.
        Returns True if created, False if already exists.
        """
        with self._lock:
            if job_id in self._jobs:
                return False
            self._jobs[job_id] = job_data
            return True

    def delete_job(self, job_id):
        """
        Atomically delete a job.
        Returns True if deleted, False if not found.
        """
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                return True
            return False

    def get_job(self, job_id):
        """
        Get a copy of job data.
        Returns dict or None if not found.
        """
        with self._lock:
            if job_id in self._jobs:
                return dict(self._jobs[job_id])
            return None

    def update_job_status(self, job_id, status):
        """
        Atomically update job status.
        Returns True if updated, False if job not found.
        """
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id]["STATUS"] = status
                return True
            return False

    def find_running_job_for_array(self, array_id):
        """
        Find if there's a running job for the given array.
        Returns (job_id, job_data_copy) or (None, None).
        Updates job status while holding lock.
        """
        with self._lock:
            for job_id, job_data in list(self._jobs.items()):
                if job_data["ID"] == array_id:
                    # Update status while we have the lock
                    self._update_status_locked(job_id, job_data)
                    if job_data["STATUS"] == "RUNNING":
                        return job_id, dict(job_data)
            return None, None

    def _update_status_locked(self, job_id, job_data):
        """
        Internal method to update status (assumes lock is held).
        """
        p = job_data["PROCESS"]
        p.join(0)
        if not p.is_alive():
            if p.exitcode == 0:
                job_data["STATUS"] = "SUCCESS"
            else:
                job_data["STATUS"] = "FAIL"

    def get_job_and_update_status(self, job_id):
        """
        Get job and update its status atomically.
        Returns job_data dict or None.
        """
        with self._lock:
            if job_id in self._jobs:
                job_data = self._jobs[job_id]
                self._update_status_locked(job_id, job_data)
                return dict(job_data)
            return None

    def get_all_jobs(self):
        """
        Get a snapshot of all jobs with updated status.
        Returns a list of (job_id, job_data_copy) tuples.
        """
        with self._lock:
            result = []
            for job_id, job_data in list(self._jobs.items()):
                # Update status while we have the lock
                self._update_status_locked(job_id, job_data)
                # Return a copy to avoid external modifications
                result.append((job_id, dict(job_data)))
            return result

    def get_running_jobs(self):
        """
        Get a snapshot of running jobs only with updated status.
        Returns a list of (job_id, job_data_copy) tuples.
        """
        with self._lock:
            result = []
            for job_id, job_data in list(self._jobs.items()):
                self._update_status_locked(job_id, job_data)
                if job_data["STATUS"] == "RUNNING":
                    result.append((job_id, dict(job_data)))
            return result


jobs = ThreadSafeJobManager()
config = {}

STARTUP_CWD = ""

NODE = None


def _lcall(command, job_id):
    """
    Call an executable and return a tuple of exitcode, stdout&stderr
    Note: command must be a list (not a string) to prevent shell injection
    """

    # Write output to a file so we can see what's going on while it's running
    f = "/tmp/%s.out" % job_id

    with open(f, "w", buffering=1) as log:  # Max buffer 1 line (text mode)
        # shell=False is the default, ensuring no shell interpretation
        exit_value = call(command, stdout=log, stderr=log, shell=False)
    return exit_value, f


def _file_name(job_id, log_dir=None):
    # If this log directory is located in /tmp, the system may remove the
    # directory after a while, making us fail to log when needed.

    if log_dir is None:
        log_dir = config["LOGDIR"]

    # Race-safe directory creation
    try:
        os.makedirs(log_dir)
    except OSError as e:
        # It's OK if directory already exists (another process created it)
        if e.errno != errno.EEXIST:
            raise
        # EEXIST is expected and fine - directory exists

    base = "%s/%s" % (log_dir, job_id)
    return base + ".out"


# Python 3.14 changed behavior where the child process does not inherit global variables by default
# thus we are passing them instead.
# see: https://github.com/python/cpython/issues/84559
#      https://docs.python.org/3.14/whatsnew/3.14.html
#      https://docs.python.org/3/library/multiprocessing.html
def _run_command(job_id, args, program, log_dir):
    ec = 0
    cmd = []

    try:
        cmd = [program]

        cmd.extend(args)

        (ec, output_file) = _lcall(cmd, job_id)
        log = _file_name(job_id, log_dir)

        # Read in output file in it's entirety
        with open(output_file, "r") as o:
            out = o.read()

        with open(log, "w") as error_file:
            json.dump(dict(EC=str(ec), OUTPUT=out), error_file)
            error_file.flush()

        # Delete file to prevent /tmp from filling up, but after we have
        # written out error file, in case we hit a bug
        os.remove(output_file)
    except Exception:
        testlib.p("job_id = %s cmd = '%s', log_dir = %s, program = %s" %
                  (job_id, str(cmd), log_dir, program))
        testlib.p(str(traceback.format_exc()))

    # This is a separate process, lets exit with the same exit code as cmd
    sys.exit(ec)


def _rs(length):
    return "".join(
        random.choice(string.ascii_lowercase) for _ in range(length))


def _load_config():
    global config
    cfg = os.path.dirname(os.path.realpath(__file__)) + "/" + "config.yaml"
    with open(cfg, "r") as array_data:
        config = yaml.safe_load(array_data.read())

    # If the user didn't specify a full path in the configuration file we
    # expect it in the same directory as this file
    if config["PROGRAM"][0] != "/":
        config["PROGRAM"] = (os.path.dirname(os.path.realpath(__file__)) +
                             "/" + config["PROGRAM"])

    # Lets make sure import external files/directories are present
    if not os.path.exists(config["PROGRAM"]):
        testlib.p("config PROGRAM %s does not exist" % config["PROGRAM"])
        sys.exit(1)

    if not (os.path.exists(config["LOGDIR"]) and os.path.isdir(
            config["LOGDIR"]) and os.access(config["LOGDIR"], os.W_OK)):
        testlib.p("config LOGDIR not preset or not a "
                  "directory %s or not writeable" % (config["LOGDIR"]))
        sys.exit(1)


def _remove_file(job_id):
    fn = _file_name(job_id)
    try:
        testlib.p("Deleting file: %s" % fn)
        os.remove(fn)
    except IOError as ioe:
        testlib.p("Error deleting file: %s, reason: %s" % (fn, str(ioe)))
        pass


# Note: _update_state and _return_state functions have been replaced
# by methods in ThreadSafeJobManager class for thread safety


class Cmds(object):
    """
    Class that handles the rest methods.
    """

    @staticmethod
    def _validate_repo_url(repo):
        """
        Validate that the repo URL is a safe git URL.
        :param repo: Repository URL to validate
        :return: True if valid, False otherwise
        """
        import re
        # Allow https and git protocols with standard git URL format
        # This prevents command injection through malicious URLs
        git_url_pattern = r'^(https?|git)://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+\.git$'
        if not re.match(git_url_pattern, repo):
            return False
        # Additional check: no shell metacharacters
        dangerous_chars = [
            ';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r'
        ]
        return not any(char in repo for char in dangerous_chars)

    @staticmethod
    def _validate_branch_name(branch):
        """
        Validate that the branch name is safe.
        :param branch: Branch name to validate
        :return: True if valid, False otherwise
        """
        import re
        # Git branch names: alphanumeric, hyphens, underscores, slashes, dots
        # No shell metacharacters allowed
        branch_pattern = r'^[a-zA-Z0-9/_.\-]+$'
        if not re.match(branch_pattern, branch):
            return False
        # Additional safety: no dangerous patterns
        dangerous_patterns = ['..', '//', '\\']
        return not any(pattern in branch for pattern in dangerous_patterns)

    @staticmethod
    def ping():
        """
        Used to see if the node manager can talk to the node.
        :return: string pong and http code 200
        """
        return "pong", 200, ""

    # Returns systems available for running tests
    @staticmethod
    def arrays():
        """
        Returns  which arrays are available.
        :return: array of tuples which gets converted into JSON and http 200
            status code.
        """
        rc = [(x["ID"], x["PLUGIN"]) for x in config["ARRAYS"]]
        return rc, 200, ""

    @staticmethod
    def running():
        """
        Returns dictionary which gets converted to JSON tests that
        are still running.
        :return: array of dictionary
            [ {"STATUS": ['RUNNING'|'SUCCESS'|'FAIL'}, "ID": <array id>,
            "JOB_ID": [a-z]{32}, "PLUGIN":'lsm plugin'}, ... ]
        """
        global jobs
        rc = []
        for job_id, job_data in jobs.get_running_jobs():
            rc.append({
                "STATUS": job_data["STATUS"],
                "ID": job_data["ID"],
                "JOB_ID": job_id,
                "PLUGIN": job_data["PLUGIN"],
            })

        return rc, 200, ""

    @staticmethod
    def job_create(repo, branch, array_id):
        """
        Submit a new test to run

        :param repo: The git repo to use
        :param branch: The git branch
        :param array_id: The test array ID
        :return:
            412 - Job already running on specified array
            400 - Input parameters are incorrect or missing
            201 - Test started
        """
        global jobs

        # Validate inputs to prevent command injection
        if not Cmds._validate_repo_url(repo):
            testlib.p("Invalid repo URL rejected: %s" % repo)
            return "", 400, "Invalid repository URL format"

        if not Cmds._validate_branch_name(branch):
            testlib.p("Invalid branch name rejected: %s" % branch)
            return "", 400, "Invalid branch name format"

        testlib.p("Running test for %s %s %s" % (repo, branch, array_id))

        if any([x for x in config["ARRAYS"] if x["ID"] == array_id]):

            # Atomically check for existing running job for this array
            existing_job_id, _ = jobs.find_running_job_for_array(array_id)
            if existing_job_id:
                return "", 412, "Job already running on array"

            # Run the job
            # Build the arguments for the script
            uri = ""
            password = ""
            plug = ""

            for a in config["ARRAYS"]:
                if a["ID"] == array_id:
                    uri = a["URI"]
                    password = a["PASSWORD"]
                    plug = a["PLUGIN"]
                    break

            # When we add rpm builds we will need client to pass
            # which 'type' too
            incoming = ("git", repo, branch, uri, password)
            job_id = _rs(32)
            p = Process(target=_run_command,
                        args=(job_id, incoming, config["PROGRAM"],
                              config["LOGDIR"]))
            p.name = "|".join(incoming)
            p.start()

            job_data = dict(STATUS="RUNNING",
                            PROCESS=p,
                            ID=array_id,
                            PLUGIN=plug)

            if not jobs.create_job(job_id, job_data):
                # Extremely unlikely: job_id collision
                testlib.p("Job ID collision for %s" % job_id)
                return "", 500, "Failed to create job (ID collision)"

            return job_id, 201, ""
        else:
            return "", 400, "Invalid array specified!"

    @staticmethod
    def jobs():
        """
        Returns all known jobs regardless of status
        :return: array of dictionaries
        """
        global jobs
        rc = []
        for job_id, job_data in jobs.get_all_jobs():
            rc.append({
                "STATUS": job_data["STATUS"],
                "ID": job_data["ID"],
                "JOB_ID": job_id,
                "PLUGIN": job_data["PLUGIN"],
            })

        return rc, 200, ""

    @staticmethod
    def job(job_id):
        """
        Get the status of the specified job
        :param job_id: ID of job to get status on
        :return: job state
        """
        global jobs
        job_data = jobs.get_job_and_update_status(job_id)
        if job_data:
            return {
                "STATUS": job_data["STATUS"],
                "ID": job_data["ID"],
                "JOB_ID": job_id,
                "PLUGIN": job_data["PLUGIN"],
            }, 200, ""
        return "", 404, "Job not found!"

    @staticmethod
    def job_completion(job_id):
        """
        Get the exit code and log file for the specified job
        :param job_id: ID of job
        :return: http status:
            200 on success
            400 if job is still running
            404 if job is not found
            json payload { "EC": <exit code>, "OUTPUT": "std out + std error"}
        """
        global jobs
        job_data = jobs.get_job_and_update_status(job_id)

        if job_data is None:
            testlib.p("Job ID %s not found in hash!" % job_id)
            return "", 404, "Job not found"

        if job_data["STATUS"] == "RUNNING":
            return "", 400, "Job still running"

        # Job is complete, retrieve log file
        log = _file_name(job_id)
        try:
            testlib.p("Retrieving log file: %s" % log)
            with open(log, "r") as foo:
                result = json.load(foo)

            return json.dumps(result), 200, ""
        except:
            testlib.p("Exception in retrieving log file!")
            testlib.p(str(traceback.format_exc()))
            # We had a job in the hash, but an error while processing
            # the log file, we will return a 404 and make sure the
            # file is indeed gone
            try:
                jobs.delete_job(job_id)
                _remove_file(job_id)
            except:
                # These aren't the errors you're looking for..., move
                # along...
                pass
            return "", 404, "Job log file not found"

    @staticmethod
    def job_delete(job_id):
        """
        Delete a test that is no longer running, cleans up in memory hash and
        removes log file from disk
        :param job_id: ID of job
        :return: http status 200 on success, else 400 if job is still running
                 or 404 if job is not found
        """
        global jobs
        job_data = jobs.get_job_and_update_status(job_id)

        if job_data is None:
            return "", 404, "Job not found"

        if job_data["STATUS"] == "RUNNING":
            return "", 400, "Job still running"

        # Job exists and is not running, safe to delete
        if jobs.delete_job(job_id):
            _remove_file(job_id)
            return "", 200, ""
        else:
            # Job was deleted between check and delete (unlikely but possible)
            return "", 404, "Job not found"

    @staticmethod
    def md5_files(files):
        """
        Return the md5 for a list of files, the file cannot contain any '/' and
        we are restricting it to the same directory as the node.py executing
        directory as we are only expecting to check files in the same directory.
        :param files: List of files
        :return: An array of md5sums in the order the files were given to us.
        """
        rc = []

        for file_name in files:
            if "/" in file_name:
                return (
                    rc,
                    412,
                    "File %s contains illegal character" % file_name,
                )

            full_fn = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   file_name)
            if os.path.exists(full_fn) and os.path.isfile(full_fn):
                rc.append(testlib.file_md5(full_fn))
            else:
                # If a file doesn't exist lets return a bogus value, then the
                # server will push the new file down.
                rc.append("File not found!")

        return rc, 200, ""

    @staticmethod
    def _update_files(tmp_dir, file_data):
        src_files = []

        # Dump the file locally to temp directory
        for i in file_data:
            fn = i["fn"]
            data = i["data"]
            md5 = i["md5"]

            if "/" in fn:
                return "", 412, "File name has directory sep. in it! %s" % fn

            tmp_file = os.path.join(tmp_dir, fn)

            with open(tmp_file, "w") as t:
                t.write(data)

            if md5 != testlib.file_md5(tmp_file):
                return "", 412, "md5 miss-match for %s" % tmp_file

            src_files.append(tmp_file)

        # Move the files into position
        for src_path_name in src_files:
            perms = None
            name = os.path.basename(src_path_name)
            dest_path_name = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), name)

            # Before we move, lets store off the perms, so we can restore them
            # after the move
            if os.path.exists(dest_path_name):
                perms = os.stat(dest_path_name).st_mode & 0o777

            testlib.p("Moving: %s -> %s" % (src_path_name, dest_path_name))
            shutil.move(src_path_name, dest_path_name)

            if perms:
                testlib.p("Setting perms: %s %s" %
                          (dest_path_name, oct(perms)))
                os.chmod(dest_path_name, perms)

        return "", 200, ""

    @staticmethod
    def update_files(file_data):
        """
        Given a file_name, the file_contents and the md5sum for the file we will
        dump the file contents to a tmp file, validate the md5 and if all is
        well we will replace the file_name with it.

        Note: file data is a hash with keys: 'fn', 'data', 'md5'

        :param file_data:
        :return: http 200 on success, else 412
        """
        # Create a temp directory
        td = tempfile.mkdtemp()

        testlib.p("Updating client files!")

        try:
            result = Cmds._update_files(td, file_data)
        except:
            result = (
                "",
                412,
                "Exception on file update %s " % str(traceback.format_exc()),
            )

        # Remove tmp directory and the files we left in it
        shutil.rmtree(td)
        return result

    @staticmethod
    def restart():
        """
        Restart the node
        :return: None
        """
        global NODE
        testlib.p("Restarting node as requested by node_manager")
        os.chdir(STARTUP_CWD)
        NODE.disconnect()
        os.execl(sys.executable, *([sys.executable] + sys.argv))


def process_request(req):
    """
    Processes the request.
    :param req: The request
    :return: Appropriate http status code.
    """
    data = ""
    ec = 0
    error_msg = ""

    if hasattr(Cmds, req.method):
        if req.args and len(req.args):
            data, ec, error_msg = getattr(Cmds, req.method)(*req.args)
        else:
            data, ec, error_msg = getattr(Cmds, req.method)()
        NODE.return_response(testlib.Response(data, ec, error_msg))
    else:
        # Bounce this back to the requester
        NODE.return_response(testlib.Response("", 404, "Command not found!"))


if __name__ == "__main__":
    # Load the available test arrays from config file
    STARTUP_CWD = os.getcwd()

    _load_config()

    server = config["SERVER_IP"]
    port = config["SERVER_PORT"]
    proxy_is_ip = config["PROXY_IS_IP"]
    use_proxy = config["USE_PROXY"]
    proxy_host = config["PROXY_HOST"]
    proxy_port = config["PROXY_PORT"]

    servers = [server, testlib.SERVER_HOSTNAME]
    connection_count = 0

    # Connect to server
    while True:

        # Round robin on IP address, starting with the one that is specified
        # in user configuration.
        server_addr = servers[connection_count % len(servers)]

        testlib.p("Attempting connection to %s:%d" % (server_addr, port))
        NODE = testlib.TestNode(
            server_addr,
            port,
            use_proxy=use_proxy,
            proxy_is_ip=proxy_is_ip,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
        )

        if NODE.connect():
            testlib.p("Connected to %s" % server_addr)
            have_connected = True
            # noinspection PyBroadException
            try:
                while True:
                    request = NODE.wait_for_request()
                    process_request(request)
            except KeyboardInterrupt:
                NODE.disconnect()
                sys.exit(0)
            except Exception:
                testlib.p(str(traceback.format_exc()))
                pass

            # This probably won't do much as socket is quite likely toast
            NODE.disconnect()
        else:
            connection_count += 1

        # If we get here we need to re-establish connection, make sure we don't
        # swamp the processor
        time.sleep(10)
