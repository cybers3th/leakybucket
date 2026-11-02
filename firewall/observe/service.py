"""Run and stop one locked local service instance per state directory."""
import argparse
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _lock(directory):
    fd = os.open(directory / 'service.pid', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    return fd


def start(directory, url, token_file):
    descriptor = _lock(directory)
    if descriptor is None:
        print(f'LeakyBucket is already running or starting. Use leakybucket status. State: {directory}')
        return False
    log_fd = None
    process = None
    try:
        log_fd = os.open(directory / 'service.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        process = subprocess.Popen([sys.executable, '-m', 'firewall.observe.service', '--lock-fd', str(descriptor),
                                    '--state-dir', str(directory)], stdin=subprocess.DEVNULL, stdout=log_fd, stderr=log_fd,
                                   start_new_session=True, close_fds=True, pass_fds=(descriptor,))
        os.ftruncate(descriptor, 0)
        os.write(descriptor, str(process.pid).encode())
        token = Path(token_file).read_text().strip()
        from .client import NoRedirect
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and process.poll() is None:
            request = urllib.request.Request(url + '/api/status', headers={'Authorization': 'Bearer ' + token})
            try:
                with opener.open(request, timeout=.5) as response:
                    state = json.loads(response.read(65536))
                if state.get('ready') is True:
                    print(f'LeakyBucket started at {url} (PID {process.pid}).')
                    print(f'Policy: {os.environ["LB_POLICY_PATH"]}')
                    mode = 'semantic classifier and built-in rules' if os.environ.get('LB_CLASSIFIER_URL') else 'built-in rules; semantic classifier is not configured'
                    print(f'Inspection: {mode}.')
                    print(f'Upstream: {os.environ["LB_UPSTREAM_URL"]}')
                    print('Model requests require a running provider at the upstream URL.')
                    print('Use leakybucket status, traces, watch, or stop.')
                    return True
            except (OSError, ValueError, urllib.error.URLError):
                time.sleep(.1)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        raise ValueError(f'Service did not become ready. See {directory / "service.log"}')
    finally:
        if log_fd is not None:
            os.close(log_fd)
        os.close(descriptor)


def stop(directory):
    if not (directory / 'service.pid').exists():
        print('LeakyBucket is not running.')
        return
    descriptor = _lock(directory)
    if descriptor is not None:
        os.close(descriptor)
        print('LeakyBucket is not running.')
        return
    pid = int((directory / 'service.pid').read_text())
    pidfd = None
    try:
        if hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'):
            pidfd = os.pidfd_open(pid)
        args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        if b'firewall.observe.service' not in args or str(directory).encode() not in args:
            raise ValueError('Service PID does not match this state directory; refusing to signal it')
        if pidfd is not None:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, FileNotFoundError):
        print('LeakyBucket is not running.')
        return
    finally:
        if pidfd is not None:
            os.close(pidfd)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        descriptor = _lock(directory)
        if descriptor is not None:
            os.close(descriptor)
            print('LeakyBucket stopped.')
            return
        time.sleep(.1)
    raise ValueError('Service is still stopping; check status or service.log')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--lock-fd', type=int, required=True)
    parser.add_argument('--state-dir', required=True)
    args = parser.parse_args()
    try:
        from firewall.serve.__main__ import main as serve
        serve()
    finally:
        os.close(args.lock_fd)


if __name__ == '__main__':
    main()
