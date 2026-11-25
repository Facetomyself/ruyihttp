# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import ipaddress
import queue
import socket
import threading
import time

from requests.exceptions import ConnectTimeout

_TCP_DELAY = 0.25
_DNS_POLL = 0.05
# libc getaddrinfo cannot be interrupted. Bound abandoned lookups separately
# from the two TCP workers, which use the native cancellable open operation.
_DNS_SLOTS = threading.BoundedSemaphore(16)


class Attempt:
    def __init__(self, deadline):
        self.deadline = deadline
        self.cancelled = threading.Event()
        self._lock = threading.Lock()
        self._interrupt = None

    def remaining(self):
        if self.cancelled.is_set():
            raise OSError("Connection attempt cancelled")
        if self.deadline is None:
            return None
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ConnectTimeout("Connection deadline elapsed")
        return remaining

    def set_interrupt(self, interrupt):
        with self._lock:
            self._interrupt = interrupt
            if self.cancelled.is_set():
                interrupt()

    def detach(self):
        with self._lock:
            self._interrupt = None

    def cancel(self):
        with self._lock:
            self.cancelled.set()
            if self._interrupt is not None:
                self._interrupt()


def race(primary, backup, timeout=None, delay=0.1, *, parent=None, deadline=None):
    started = time.monotonic()
    if parent is not None:
        deadline = parent.deadline
    elif deadline is None and timeout is not None:
        deadline = started + timeout
    attempts = [Attempt(deadline), Attempt(deadline)]
    condition = threading.Condition()
    completed = {}
    winner = []
    stopped = False

    def run(index, factory):
        connection = None
        error = None
        try:
            if index:
                with condition:
                    while not stopped and not winner and 0 not in completed:
                        remaining = started + delay - time.monotonic()
                        if remaining <= 0:
                            break
                        condition.wait(remaining)
                    if stopped or winner:
                        return
            attempts[index].remaining()
            connection = factory(attempts[index])
        except Exception as caught:
            error = caught
        finally:
            attempts[index].detach()
            with condition:
                completed[index] = error
                if connection is not None and not stopped and not winner:
                    winner.append(connection)
                    connection = None
                condition.notify_all()
            if connection is not None:
                connection.close()

    def wake():
        with condition:
            condition.notify_all()

    names = (
        ("necko-tcp-first", "necko-tcp-fallback")
        if parent is not None
        else ("necko-connect-h3", "necko-connect-tcp")
    )
    threads = [
        threading.Thread(target=run, args=(i, factory), name=names[i], daemon=True)
        for i, factory in enumerate((primary, backup))
    ]
    started_threads = []
    if parent is not None:
        parent.set_interrupt(wake)
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        with condition:
            while not winner and len(completed) != 2:
                if parent is not None:
                    remaining = parent.remaining()
                else:
                    remaining = (
                        None if deadline is None else deadline - time.monotonic()
                    )
                    if remaining is not None and remaining <= 0:
                        raise ConnectTimeout("Connection deadline elapsed")
                condition.wait(remaining)
            if parent is not None:
                parent.remaining()
            elif deadline is not None and time.monotonic() >= deadline:
                raise ConnectTimeout("Connection deadline elapsed")
            if winner:
                stopped = True
                return winner.pop()
            raise completed.get(1) or completed.get(0) or OSError("Connection failed")
    finally:
        with condition:
            stopped = True
            orphan = winner.pop() if winner else None
            condition.notify_all()
        if parent is not None:
            parent.detach()
        for attempt in attempts:
            attempt.cancel()
        if orphan is not None:
            orphan.close()
        if parent is None:
            for thread in started_threads:
                # A cancelled loser cleans up its own late result. Do not extend a
                # finite caller deadline merely to wait for that housekeeping.
                grace = (
                    0.1
                    if deadline is None
                    else min(0.1, max(0, deadline - time.monotonic()))
                )
                thread.join(timeout=grace)


def resolve_addresses(
    host, port, attempt, socktype=socket.SOCK_STREAM, **lookup_options
):
    """Resolve once under the caller's deadline; return ordered numeric addresses by family."""
    attempt.remaining()
    try:
        numeric = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        family = socket.AF_INET if numeric.version == 4 else socket.AF_INET6
        return {family: [host]}

    def wait_slice():
        remaining = attempt.remaining()
        return _DNS_POLL if remaining is None else min(_DNS_POLL, remaining)

    slots = _DNS_SLOTS
    while not slots.acquire(timeout=wait_slice()):
        pass
    results = queue.Queue(maxsize=1)

    def resolve():
        try:
            records = socket.getaddrinfo(host, port, type=socktype, **lookup_options)
            results.put((records, None))
        except Exception as error:
            results.put((None, error))
        finally:
            slots.release()

    try:
        attempt.remaining()
        threading.Thread(target=resolve, name="necko-resolve", daemon=True).start()
    except BaseException:
        slots.release()
        raise
    while True:
        try:
            records, error = results.get(timeout=wait_slice())
            break
        except queue.Empty:
            pass
    attempt.remaining()
    if error is not None:
        raise error
    families = {}
    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = sockaddr[0]
        if family == socket.AF_INET6 and sockaddr[3] and "%" not in address:
            address += f"%{sockaddr[3]}"
        families.setdefault(family, {})[address] = None
    if not families:
        raise socket.gaierror(f"No usable IP addresses for {host}")
    return {family: list(addresses) for family, addresses in families.items()}


def connect_tcp(host, port, attempt, open_socket, resolved=None):
    """Dial the same DNS answer used for coalescing, or resolve the first TCP hop."""
    if resolved is None:
        resolved = resolve_addresses(host, port, attempt)
    groups = list(resolved.values())

    def lane(addresses):
        def open_group(current):
            for index, address in enumerate(addresses):
                remaining = current.remaining()
                count = len(addresses) - index
                # Leave time for later addresses in this family even if one
                # route stalls. The last candidate gets the remaining budget.
                limit = remaining
                if count > 1:
                    limit = 1.0 if remaining is None else remaining / count
                try:
                    return open_socket(address, limit, current)
                except OSError:
                    if count == 1 or current.cancelled.is_set():
                        raise

        return open_group

    primary = lane(groups[0])
    if len(groups) == 1:
        return primary(attempt)
    remaining = attempt.remaining()
    delay = _TCP_DELAY if remaining is None else min(_TCP_DELAY, remaining / 2)
    return race(primary, lane(groups[1]), remaining, delay, parent=attempt)
