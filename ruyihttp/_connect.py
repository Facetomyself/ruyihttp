# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import threading
import time

from requests.exceptions import ConnectTimeout


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


def race(primary, backup, timeout, delay=0.1):
    started = time.monotonic()
    deadline = None if timeout is None else started + timeout
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

    threads = [
        threading.Thread(
            target=run, args=(0, primary), name="necko-connect-h3", daemon=True
        ),
        threading.Thread(
            target=run, args=(1, backup), name="necko-connect-tcp", daemon=True
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        with condition:
            while not winner and len(completed) != 2:
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise ConnectTimeout("Connection deadline elapsed")
                condition.wait(remaining)
            if winner:
                return winner[0]
            raise completed.get(1) or completed.get(0) or OSError("Connection failed")
    finally:
        with condition:
            stopped = True
            condition.notify_all()
        for attempt in attempts:
            attempt.cancel()
        for thread in threads:
            thread.join(timeout=0.1)
