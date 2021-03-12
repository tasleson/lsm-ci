"""
Used for testing the service locally
"""

import argparse
import hashlib
import hmac
import os
import requests
import json

GIT_SECRET = os.getenv("GIT_SECRET", "")
PORT_NUM = os.getenv("PORT_NUM", "43301")
IP_ADDRESS = os.getenv("IP_ADDRESS", "127.0.0.1")


def gen_signature(data):
    """
    Generate the signature for the data.
    :param data: Data to generate signature for
    :return: "sha1=<hexdigest>"
    """
    h = hmac.new(GIT_SECRET.encode("utf-8"), data.encode("utf-8"), hashlib.sha1)
    s = "sha1=" + h.hexdigest()
    return s.encode("utf-8")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="github event creation")
    parser.add_argument(
        "--clone_url",
        dest="clone_url",
        default="https://github.com/tasleson/libstoragemgmt.git",
    )

    parser.add_argument("--branch", dest="branch", default="master")
    parser.add_argument(
        "--sha1",
        dest="sha1",
        default="4a956debabed9d02e7c076d85d1f2d18eb11b549",
    )

    args = parser.parse_args()

    url = "http://%s:%s/event_handler" % (IP_ADDRESS, PORT_NUM)

    head = {
        "Content-type": "application/json",
        "X-Hub-Signature": "",
        "X-Github-Event": "pull_request",
    }

    body = dict()
    body["pull_request"] = dict()
    body["pull_request"]["base"] = dict()
    body["pull_request"]["head"] = dict()

    body["pull_request"]["base"]["repo"] = dict()
    body["pull_request"]["head"]["repo"] = dict()

    body["pull_request"]["base"]["repo"][
        "full_name"
    ] = "libstorage/libstoragemgmt"

    body["pull_request"]["head"]["repo"]["clone_url"] = args.clone_url
    body["pull_request"]["head"]["sha"] = args.sha1
    body["pull_request"]["head"]["ref"] = args.branch

    body_json = json.dumps(body)

    head["X-Hub-Signature"] = gen_signature(body_json)

    response = requests.post(
        url=url, headers=head, data=body_json.encode("utf-8")
    )

    print("status = %d" % int(response.status_code))
