# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from urllib3.exceptions import ProtocolError

MAX_REQUEST_ATTEMPTS = 10


class Reset(ProtocolError):
    pass


class Rejected(Reset):
    """The protocol establishes that the request was not processed."""


class Http1Required(Reset):
    """The peer requests HTTP/1.1, without establishing processing state."""


class Http1RequiredUnprocessed(Http1Required, Rejected):
    """HTTP/1.1 is required and the request was not processed."""


class DirectRouteReset(Reset):
    pass


class Http3ProtocolError(Reset):
    """An HTTP/3 connection closed with an error before a response arrived.

    Firefox 159 can retry such requests over TCP with HTTP/3 disabled; sessions
    imitating 158 convert it to a plain ProtocolError instead.
    """


def restartable(error, method, exchange):
    received = getattr(
        exchange, "received_data", getattr(error, "_necko_received", False)
    )
    if received:
        return False
    if isinstance(error, Rejected):
        return True
    # A pooled socket or a missing response says nothing about whether the
    # peer processed the request. Treat unknown write state as possibly sent.
    sent = getattr(exchange, "sent_data", getattr(error, "_necko_sent", True))
    return isinstance(error, Reset) and (
        method in {"GET", "HEAD", "OPTIONS", "TRACE", "PROPFIND", "REPORT", "SEARCH"}
        or not sent
    )
