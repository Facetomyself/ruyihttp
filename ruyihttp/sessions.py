# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
from urllib.parse import urlsplit

from requests.exceptions import ProxyError
from requests.sessions import Session as RequestsSession, merge_setting
from requests.utils import resolve_proxies, select_proxy

from . import _firefox
from ._transport import HTTPAdapter, is_masque_proxy, masque_route_id


class Session(RequestsSession):
    __attrs__ = RequestsSession.__attrs__ + [
        "timeout",
        "context",
        "document_url",
        "user_activation",
        "firefox",
        "proxy_verify",
        "masque_path_template",
    ]

    def __init__(
        self,
        library_path=None,
        headers=None,
        timeout=None,
        verify=True,
        auth=None,
        context="navigation",
        document_url=None,
        user_activation=True,
        firefox=None,
        *,
        proxy_verify=True,
        masque_path_template=None,
    ):
        super().__init__()
        self.proxy_verify = proxy_verify
        self.masque_path_template = masque_path_template
        self.firefox = _firefox.firefox_version(firefox)
        if context not in ("navigation", "fetch"):
            raise ValueError("context must be navigation or fetch")
        self.context = context
        self.document_url = document_url
        self.user_activation = bool(user_activation)
        self.headers = _firefox.default_headers(context, self.firefox)
        self.cookies = _firefox.cookie_jar(context, document_url)
        for adapter in self.adapters.values():
            adapter.close()
        adapter = HTTPAdapter(library_path=library_path, firefox=self.firefox)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
        self.timeout = timeout
        self.verify = verify
        self.auth = auth
        if headers:
            self.headers.update(headers)

    def prepare_request(self, request):
        prepared = super().prepare_request(request)
        prepared._firefox_cookie_header = (
            "Cookie" not in (request.headers or {}) and "Cookie" not in self.headers
        )
        _firefox.apply_headers(
            prepared, self.context, self.document_url, self.user_activation,
            self.firefox,
        )
        _firefox.apply_cookies(prepared, self.context, self.document_url)
        return prepared

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Requests fills per-request proxy defaults from the environment before
        # merging Session.proxies. Preserve an explicitly selected UDP route:
        # HTTPS_PROXY or ALL_PROXY must never substitute an ordinary TCP proxy.
        # Leave environment CA resolution and all non-MASQUE requests untouched.
        declared = dict(proxies or {})
        configured = merge_setting(declared, self.proxies) or {}
        explicit = select_proxy(url, declared)
        if is_masque_proxy(explicit):
            target = urlsplit(url)
            configured[f'{target.scheme}://{target.hostname}'] = explicit
        if not is_masque_proxy(select_proxy(url, configured)):
            return super().merge_environment_settings(url, declared, stream, verify, cert)
        # In particular do not ask a platform PAC/bypass implementation to
        # resolve the origin before discarding its answer. Explicit trust wins.
        origin_verify = merge_setting(verify, self.verify)
        if self.trust_env and origin_verify is True:
            origin_verify = os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('CURL_CA_BUNDLE') or True
        return {'proxies': configured, 'stream': merge_setting(stream, self.stream),
                'verify': origin_verify, 'cert': merge_setting(cert, self.cert)}

    def rebuild_proxies(self, prepared_request, proxies):
        if is_masque_proxy(select_proxy(prepared_request.url, proxies or {})):
            prepared_request.headers.pop('Proxy-Authorization', None)
            return dict(proxies)
        return super().rebuild_proxies(prepared_request, proxies)

    def rebuild_auth(self, prepared_request, response):
        super().rebuild_auth(prepared_request, response)
        previous = response.request
        route = getattr(response, '_ruyi_masque_route', None)
        if route is not None:
            # Requests may prepare a next request even when allow_redirects=False.
            # Mark it now; enforce the same route only if/when it is sent.
            prepared_request._ruyi_masque_route = route
            prepared_request.headers.pop('Proxy-Authorization', None)
        prepared_request._firefox_explicit = getattr(
            previous, "_firefox_explicit", set()
        )
        prepared_request._firefox_cookie_header = True
        _firefox.apply_headers(
            prepared_request, self.context, self.document_url, self.user_activation,
            self.firefox,
        )
        _firefox.apply_cookies(prepared_request, self.context, self.document_url)

    def send(self, request, **kwargs):
        if 'proxies' not in kwargs:
            kwargs['proxies'] = (dict(self.proxies) if is_masque_proxy(select_proxy(request.url, self.proxies))
                                 else resolve_proxies(request, self.proxies, self.trust_env))
        selected = select_proxy(request.url, kwargs['proxies'] or {})
        required = getattr(request, '_ruyi_masque_route', None)
        masque = is_masque_proxy(selected)
        proxy_verify = kwargs.pop('proxy_verify', getattr(self, 'proxy_verify', True))
        template = kwargs.pop('masque_path_template', getattr(self, 'masque_path_template', None))
        if required is not None and (not masque or urlsplit(request.url).scheme != 'https' or
                                     masque_route_id(selected, proxy_verify, template) != required):
            raise ProxyError('Redirect would leave the authenticated MASQUE route', request=request)
        if masque:
            if not isinstance(self.get_adapter(request.url), HTTPAdapter):
                raise ProxyError('Selected adapter does not implement MASQUE', request=request)
            kwargs['proxy_verify'] = proxy_verify
            kwargs['masque_path_template'] = template
        _firefox.apply_headers(
            request, self.context, self.document_url, self.user_activation,
            self.firefox,
        )
        _firefox.apply_cookies(request, self.context, self.document_url)
        if kwargs.get("timeout") is None and self.timeout is not None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


def session(firefox=None):
    return Session(firefox=firefox)
