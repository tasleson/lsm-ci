# lsm-ci
Github continuous integration service for libStorageMgmt

This service is based on the information available from: https://developer.github.com/guides/building-a-ci-server/ except that it's written in python instead of ruby.  These examples use http://bottlepy.org and http://www.python-requests.org

Some interesting pieces of functionality that others may want to leverage (see actual code for more detail, these are excerpts):

**Setting a status on a commit using the python 'requests' library**
```python
def _create_status(repo, sha1, state, desc, context, log_url=None):
    """
    Reports status back to github.
    """
    if '/' not in repo:
        raise Exception("Expecting repo to be in form user/repo %s" % repo)

    url = 'https://api.github.com/repos/%s/statuses/%s' % (repo, sha1)
    data = {'state': state, "description": desc, "context": context}

    if log_url:
        data["target_url"] = log_url

    r = requests.post(url, auth=(USER, TOKEN), json=data)
    if r.status_code == 201:
        print('We updated status %s' % str(data))
    else:
        print("Unexpected error on setting status %d" % r.status_code)

```
**Verifying a sha1 payload signature**
```python
def _verify_signature(payload_body, header_signature):
    """
    Verify the payload using our shared secret with github
    """
    h = hmac.new(GIT_SECRET, payload_body, hashlib.sha1)
    signature = 'sha1=' + h.hexdigest()
    try:
        # Python 2.7 and later have this which is suggested
        return hmac.compare_digest(signature, header_signature)
    except AttributeError:
        return _tscmp(signature, header_signature)
```

**Handling the event from github (using python bottle)**
```python
@route('/event_handler', method='POST')
def e_handler():
    """
    The callback for the handler registered with github
    """
    # Check secret before we do anything
    if not _verify_signature(request.body.read(),
                             request.headers['X-Hub-Signature']):
        response.status = 500
        return

    if request.headers['X-Github-Event'] == 'pull_request':
        repo = request.json["pull_request"]["base"]["repo"]["full_name"]
        sha = request.json["pull_request"]['head']['sha']
        branch = request.json["pull_request"]['head']['ref']
        
        # Set statuses etc. and run tests

    else:
        print("Got an unexpected header from github")
        for k, v in request.headers.items():
            print('%s:%s' % (str(k), str(v)))
        print(request.json)
```
