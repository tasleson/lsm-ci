#!/usr/bin/python3
"""
Standalone test file to exercise all information retrieval endpoints in node_manager.py

Tests the following GET endpoints:
- /completed - Returns completed requests from work_log
- /processing - Returns what's currently being processed
- /nodes - Returns connected clients/arrays
- /stats - Returns information on current request queue size
- /queue - Returns what's in the request queue
- /log/<log_file> - Fetches a log file

Supports both single test runs and multi-threaded stress testing.

Usage:
    # Single test run
    python3 test_node_manager_endpoints.py [--host HOST] [--port PORT]

    # Multi-threaded stress test
    python3 test_node_manager_endpoints.py --threads N --iterations M

    # Run forever (until Ctrl+C)
    python3 test_node_manager_endpoints.py --threads N --forever

Examples:
    # Single run with verbose output
    python3 test_node_manager_endpoints.py --host localhost --port 43301 --verbose

    # Stress test with 10 threads, 100 iterations each
    python3 test_node_manager_endpoints.py --threads 10 --iterations 100

    # Stress test running forever with 5 threads
    python3 test_node_manager_endpoints.py --threads 5 --forever
"""

import requests
import json
import sys
import argparse
import time
import threading
from collections import defaultdict


class NodeManagerEndpointTester:
    """Test all information retrieval endpoints in node_manager.py"""

    def __init__(self, host="localhost", port="43301", quiet=False):
        self.base_url = f"http://{host}:{port}"
        self.test_results = []
        self.passed = 0
        self.failed = 0
        self.quiet = quiet
        self.lock = threading.Lock()  # For thread-safe counter updates
        # Timing statistics: endpoint -> list of response times
        self.timing_stats = defaultdict(list)

    def log_result(self, endpoint, success, message, response_data=None, response_time=None):
        """Log test result (thread-safe)"""
        status = "PASS" if success else "FAIL"
        result = {
            "endpoint": endpoint,
            "status": status,
            "message": message,
            "response_data": response_data,
            "response_time": response_time
        }

        with self.lock:
            self.test_results.append(result)
            if success:
                self.passed += 1
            else:
                self.failed += 1

            # Record timing statistics for successful requests
            if success and response_time is not None:
                self.timing_stats[endpoint].append(response_time)

        if not self.quiet:
            timing_str = f" ({response_time*1000:.2f}ms)" if response_time is not None else ""
            if success:
                print(f"✓ {status}: {endpoint} - {message}{timing_str}")
            else:
                print(f"✗ {status}: {endpoint} - {message}{timing_str}")

    def test_endpoint(self, path, description, expected_status=200, validate_json=True):
        """
        Generic test for an endpoint

        Args:
            path: URL path (e.g., "/stats")
            description: Human-readable description of the test
            expected_status: Expected HTTP status code (default 200)
            validate_json: Whether to validate JSON response (default True)

        Returns:
            Response object if successful, None otherwise
        """
        url = f"{self.base_url}{path}"

        try:
            # Measure response time
            start_time = time.time()
            response = requests.get(url, timeout=5)
            response_time = time.time() - start_time

            # Check status code
            if response.status_code != expected_status:
                self.log_result(
                    path,
                    False,
                    f"Expected status {expected_status}, got {response.status_code}",
                    response_time=response_time
                )
                return None

            # Validate JSON if required
            if validate_json:
                try:
                    data = response.json()
                    self.log_result(
                        path,
                        True,
                        description,
                        data,
                        response_time=response_time
                    )
                    return response
                except json.JSONDecodeError as e:
                    self.log_result(
                        path,
                        False,
                        f"Invalid JSON response: {e}",
                        response_time=response_time
                    )
                    return None
            else:
                # Non-JSON response (e.g., HTML)
                self.log_result(
                    path,
                    True,
                    description,
                    f"Response length: {len(response.text)} bytes",
                    response_time=response_time
                )
                return response

        except requests.exceptions.ConnectionError:
            self.log_result(
                path,
                False,
                f"Connection failed - is server running at {self.base_url}?"
            )
            return None
        except requests.exceptions.Timeout:
            self.log_result(
                path,
                False,
                "Request timed out"
            )
            return None
        except Exception as e:
            self.log_result(
                path,
                False,
                f"Unexpected error: {e}"
            )
            return None

    def test_completed(self):
        """Test /completed endpoint"""
        response = self.test_endpoint(
            "/completed",
            "Retrieved completed requests"
        )

        if response and not self.quiet:
            data = response.json()
            # Validate it's a list
            if isinstance(data, list):
                print(f"  → Found {len(data)} completed requests")
            else:
                print(f"  → Warning: Expected list, got {type(data).__name__}")

    def test_processing(self):
        """Test /processing endpoint"""
        response = self.test_endpoint(
            "/processing",
            "Retrieved processing requests"
        )

        if response and not self.quiet:
            data = response.json()
            # Validate it's a list
            if isinstance(data, list):
                print(f"  → Found {len(data)} processing requests")
            else:
                print(f"  → Warning: Expected list, got {type(data).__name__}")

    def test_nodes(self):
        """Test /nodes endpoint"""
        response = self.test_endpoint(
            "/nodes",
            "Retrieved connected nodes/arrays"
        )

        if response and not self.quiet:
            data = response.json()
            # Validate it's a list
            if isinstance(data, list):
                print(f"  → Found {len(data)} connected arrays")
                if data:
                    print(f"  → Sample array: {data[0]}")
            else:
                print(f"  → Warning: Expected list, got {type(data).__name__}")

    def test_stats(self):
        """Test /stats endpoint"""
        response = self.test_endpoint(
            "/stats",
            "Retrieved queue statistics"
        )

        if response and not self.quiet:
            data = response.json()
            # Validate it's a dict with QUEUE_SIZE
            if isinstance(data, dict):
                if "QUEUE_SIZE" in data:
                    print(f"  → Queue size: {data['QUEUE_SIZE']}")
                else:
                    print(f"  → Warning: Missing 'QUEUE_SIZE' key")
            else:
                print(f"  → Warning: Expected dict, got {type(data).__name__}")

    def test_queue(self):
        """Test /queue endpoint"""
        response = self.test_endpoint(
            "/queue",
            "Retrieved queue contents"
        )

        if response and not self.quiet:
            data = response.json()
            # Validate it's a list
            if isinstance(data, list):
                print(f"  → Found {len(data)} items in queue")
                if data:
                    print(f"  → Sample queue item keys: {list(data[0].keys())}")
            else:
                print(f"  → Warning: Expected list, got {type(data).__name__}")

    def test_log_nonexistent(self):
        """Test /log/<log_file> endpoint with nonexistent file"""
        # Test with a valid-format but nonexistent log file
        # Log files must match pattern [a-z]{32}.html
        fake_log = "a" * 32 + ".html"

        # This should return 500 for nonexistent file
        self.test_endpoint(
            f"/log/{fake_log}",
            "Correctly handled nonexistent log file",
            expected_status=500,
            validate_json=False
        )

    def test_log_invalid_format(self):
        """Test /log/<log_file> endpoint with invalid format"""
        # Test with invalid format (should fail validation)
        invalid_log = "invalid_log_name.html"

        # This should return 500 for invalid format
        self.test_endpoint(
            f"/log/{invalid_log}",
            "Correctly rejected invalid log file format",
            expected_status=500,
            validate_json=False
        )

    def run_all_tests(self):
        """Run all endpoint tests"""
        if not self.quiet:
            print(f"\n{'='*70}")
            print(f"Testing Node Manager Information Retrieval Endpoints")
            print(f"Base URL: {self.base_url}")
            print(f"{'='*70}\n")

        # Test each endpoint
        if not self.quiet:
            print("Testing /completed endpoint:")
        self.test_completed()
        if not self.quiet:
            print()

        if not self.quiet:
            print("Testing /processing endpoint:")
        self.test_processing()
        if not self.quiet:
            print()

        if not self.quiet:
            print("Testing /nodes endpoint:")
        self.test_nodes()
        if not self.quiet:
            print()

        if not self.quiet:
            print("Testing /stats endpoint:")
        self.test_stats()
        if not self.quiet:
            print()

        if not self.quiet:
            print("Testing /queue endpoint:")
        self.test_queue()
        if not self.quiet:
            print()

        if not self.quiet:
            print("Testing /log/<log_file> endpoint (nonexistent file):")
        self.test_log_nonexistent()
        if not self.quiet:
            print()

        if not self.quiet:
            print("Testing /log/<log_file> endpoint (invalid format):")
        self.test_log_invalid_format()
        if not self.quiet:
            print()

        # Print summary
        if not self.quiet:
            print(f"{'='*70}")
            print(f"Test Summary")
            print(f"{'='*70}")
            print(f"Total tests: {self.passed + self.failed}")
            print(f"Passed: {self.passed}")
            print(f"Failed: {self.failed}")
            print(f"{'='*70}\n")

            # Print timing statistics
            self.print_timing_stats()

            if self.failed > 0:
                print("Failed tests:")
                for result in self.test_results:
                    if result["status"] == "FAIL":
                        print(f"  - {result['endpoint']}: {result['message']}")
                print()

        return 0 if self.failed == 0 else 1

    def print_timing_stats(self):
        """Print timing statistics for all endpoints"""
        if not self.timing_stats:
            return

        print(f"{'='*70}")
        print(f"Response Time Statistics")
        print(f"{'='*70}")
        print(f"{'Endpoint':<30} {'Min (ms)':>10} {'Max (ms)':>10} {'Avg (ms)':>10} {'Count':>8}")
        print(f"{'-'*70}")

        # Calculate and display stats for each endpoint
        for endpoint, times in sorted(self.timing_stats.items()):
            if times:
                min_time = min(times) * 1000  # Convert to ms
                max_time = max(times) * 1000
                avg_time = (sum(times) / len(times)) * 1000
                count = len(times)

                print(f"{endpoint:<30} {min_time:>10.2f} {max_time:>10.2f} {avg_time:>10.2f} {count:>8}")

        # Overall statistics
        all_times = []
        for times in self.timing_stats.values():
            all_times.extend(times)

        if all_times:
            print(f"{'-'*70}")
            overall_min = min(all_times) * 1000
            overall_max = max(all_times) * 1000
            overall_avg = (sum(all_times) / len(all_times)) * 1000
            overall_count = len(all_times)

            print(f"{'OVERALL':<30} {overall_min:>10.2f} {overall_max:>10.2f} {overall_avg:>10.2f} {overall_count:>8}")
        print(f"{'='*70}\n")

    def get_timing_summary(self):
        """Get timing statistics as a dictionary (for multi-threaded aggregation)"""
        return dict(self.timing_stats)

    def run_single_iteration(self):
        """Run a single iteration of all tests (for stress testing)"""
        self.test_completed()
        self.test_processing()
        self.test_nodes()
        self.test_stats()
        self.test_queue()
        self.test_log_nonexistent()
        self.test_log_invalid_format()


def worker_thread(host, port, iterations, thread_id, stats_lock, thread_stats, run_forever):
    """Worker thread for stress testing"""
    tester = NodeManagerEndpointTester(host=host, port=port, quiet=True)
    iteration = 0

    try:
        while run_forever or iteration < iterations:
            iteration += 1
            tester.run_single_iteration()

            # Update stats periodically (every 10 iterations)
            if iteration % 10 == 0:
                with stats_lock:
                    thread_stats[thread_id]['iterations'] = iteration
                    thread_stats[thread_id]['passed'] = tester.passed
                    thread_stats[thread_id]['failed'] = tester.failed

        # Final stats update including timing data
        with stats_lock:
            thread_stats[thread_id]['iterations'] = iteration
            thread_stats[thread_id]['passed'] = tester.passed
            thread_stats[thread_id]['failed'] = tester.failed
            thread_stats[thread_id]['timing'] = tester.get_timing_summary()
            thread_stats[thread_id]['completed'] = True

    except KeyboardInterrupt:
        # Update stats on interrupt
        with stats_lock:
            thread_stats[thread_id]['iterations'] = iteration
            thread_stats[thread_id]['passed'] = tester.passed
            thread_stats[thread_id]['failed'] = tester.failed
            thread_stats[thread_id]['timing'] = tester.get_timing_summary()
            thread_stats[thread_id]['completed'] = True


def run_stress_test(host, port, threads, iterations, run_forever):
    """Run multi-threaded stress test"""
    print(f"\n{'='*70}")
    print(f"Node Manager Stress Test")
    print(f"{'='*70}")
    print(f"Target: http://{host}:{port}")
    print(f"Threads: {threads}")
    if run_forever:
        print(f"Mode: Running forever (Ctrl+C to stop)")
    else:
        print(f"Iterations per thread: {iterations}")
        print(f"Total iterations: {threads * iterations}")
    print(f"{'='*70}\n")

    stats_lock = threading.Lock()
    thread_stats = defaultdict(lambda: {'iterations': 0, 'passed': 0, 'failed': 0, 'completed': False})

    # Create and start worker threads
    worker_threads = []
    for i in range(threads):
        t = threading.Thread(
            target=worker_thread,
            args=(host, port, iterations, i, stats_lock, thread_stats, run_forever),
            name=f"Worker-{i}"
        )
        t.start()
        worker_threads.append(t)

    print(f"Started {threads} worker threads...\n")

    # Monitor progress
    try:
        while True:
            time.sleep(2)  # Update every 2 seconds

            with stats_lock:
                total_iterations = sum(s['iterations'] for s in thread_stats.values())
                total_passed = sum(s['passed'] for s in thread_stats.values())
                total_failed = sum(s['failed'] for s in thread_stats.values())
                completed_threads = sum(1 for s in thread_stats.values() if s['completed'])

            if run_forever:
                print(f"\rIterations: {total_iterations} | Passed: {total_passed} | Failed: {total_failed} | Active threads: {threads - completed_threads}", end='', flush=True)
            else:
                print(f"\rProgress: {total_iterations}/{threads * iterations} | Passed: {total_passed} | Failed: {total_failed}", end='', flush=True)

            # Check if all threads completed (only in non-forever mode)
            if not run_forever and completed_threads == threads:
                break

    except KeyboardInterrupt:
        print("\n\nInterrupted by user, waiting for threads to finish...\n")

    # Wait for all threads to complete
    for t in worker_threads:
        t.join()

    # Final statistics
    print("\n")
    print(f"{'='*70}")
    print(f"Stress Test Complete")
    print(f"{'='*70}")

    with stats_lock:
        total_iterations = sum(s['iterations'] for s in thread_stats.values())
        total_passed = sum(s['passed'] for s in thread_stats.values())
        total_failed = sum(s['failed'] for s in thread_stats.values())

        print(f"Total iterations: {total_iterations}")
        print(f"Total passed: {total_passed}")
        print(f"Total failed: {total_failed}")
        print(f"Success rate: {(total_passed / (total_passed + total_failed) * 100):.2f}%" if (total_passed + total_failed) > 0 else "N/A")
        print(f"\nPer-thread statistics:")
        for thread_id, stats in sorted(thread_stats.items()):
            print(f"  Thread {thread_id}: {stats['iterations']} iterations, {stats['passed']} passed, {stats['failed']} failed")
        print(f"{'='*70}\n")

        # Aggregate timing statistics from all threads
        aggregated_timings = defaultdict(list)
        for stats in thread_stats.values():
            if 'timing' in stats:
                for endpoint, times in stats['timing'].items():
                    aggregated_timings[endpoint].extend(times)

        # Display aggregated timing statistics
        if aggregated_timings:
            print(f"{'='*70}")
            print(f"Response Time Statistics (Aggregated from all threads)")
            print(f"{'='*70}")
            print(f"{'Endpoint':<30} {'Min (ms)':>10} {'Max (ms)':>10} {'Avg (ms)':>10} {'Count':>8}")
            print(f"{'-'*70}")

            for endpoint, times in sorted(aggregated_timings.items()):
                if times:
                    min_time = min(times) * 1000
                    max_time = max(times) * 1000
                    avg_time = (sum(times) / len(times)) * 1000
                    count = len(times)
                    print(f"{endpoint:<30} {min_time:>10.2f} {max_time:>10.2f} {avg_time:>10.2f} {count:>8}")

            # Overall statistics
            all_times = []
            for times in aggregated_timings.values():
                all_times.extend(times)

            if all_times:
                print(f"{'-'*70}")
                overall_min = min(all_times) * 1000
                overall_max = max(all_times) * 1000
                overall_avg = (sum(all_times) / len(all_times)) * 1000
                overall_count = len(all_times)
                print(f"{'OVERALL':<30} {overall_min:>10.2f} {overall_max:>10.2f} {overall_avg:>10.2f} {overall_count:>8}")
            print(f"{'='*70}\n")

    return 0 if total_failed == 0 else 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Test all information retrieval endpoints in node_manager.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single run with all tests
  %(prog)s --host localhost --port 43301

  # Stress test with 10 threads, 100 iterations each
  %(prog)s --threads 10 --iterations 100

  # Stress test running forever
  %(prog)s --threads 5 --forever

  # Stress test on remote server
  %(prog)s --host 192.168.1.100 --threads 20 --iterations 50
        """
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host where node_manager is running (default: localhost)"
    )
    parser.add_argument(
        "--port",
        default="43301",
        help="Port where node_manager is running (default: 43301)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed response data (only for single-threaded mode)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=1,
        help="Number of concurrent threads for stress testing (default: 1)"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of iterations per thread (default: 1)"
    )
    parser.add_argument(
        "--forever",
        action="store_true",
        help="Run stress test forever (until Ctrl+C)"
    )

    args = parser.parse_args()

    # Determine if this is a stress test (multiple threads/iterations or forever mode)
    is_stress_test = args.threads > 1 or args.iterations > 1 or args.forever

    if is_stress_test:
        # Run stress test
        exit_code = run_stress_test(
            args.host,
            args.port,
            args.threads,
            args.iterations,
            args.forever
        )
    else:
        # Run normal single test
        tester = NodeManagerEndpointTester(host=args.host, port=args.port)
        exit_code = tester.run_all_tests()

        if args.verbose:
            print("\nDetailed Results:")
            print(json.dumps(tester.test_results, indent=2))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
