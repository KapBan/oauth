import json
import os

import requests
from .exceptions import OAuthValidationException
from .settings import AUTH_SERVER_URL, AUTH_SERVER_TOKEN_URL, RESOURCE_SERVER_URL


class LazyLogger:
    """it's lazy because writes logs directly to file :) really sorry for that"""
    def __init__(self):
        self._log_dir_path = os.path.dirname(__file__)
        self.info_log_file = os.path.join(self._log_dir_path, 'logs', 'info.log')
        self.error_log_file = os.path.join(self._log_dir_path, 'logs', 'error.log')
        self.serializable_types = [
            dict,
            list,
            tuple,
            set
        ]

    def _encode(self, payload):
        if type(payload) in self.serializable_types:
            return json.dumps(payload)
        else:
            return str(payload)

    def _log_to_file(self, filename, text):
        with open(filename, 'a') as log_file:
            log_file.write(text)

    def info(self, *args, **kwargs):
        self._log_to_file(
            self.info_log_file,
            self._encode(kwargs)
        )

    def error(self, *args, **kwargs):
        self._log_to_file(
            self.error_log_file,
            self._encode(kwargs)
        )


class OAuthTransport:
    def __init__(self, *args, **kwargs):
        try:
            self.client_id = kwargs['client_id']
            self.client_secret = kwargs['client_secret']
            self.client_scope = kwargs['client_scope']
        except ValueError:
            raise OAuthValidationException(
                'Wrong credentials\' set',
                **kwargs
            )

        self.auth_server_url = AUTH_SERVER_URL
        self.auth_server_token_url = AUTH_SERVER_TOKEN_URL
        self.resource_server_url = RESOURCE_SERVER_URL

        self._access_token = None

        self.logger = LazyLogger()

    # refreshes token and sets it to class field (actually it executes each time)
    def _refresh_token(self):
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials',
            'scope': self.client_scope
        }
        headers = {'accept': 'application/json'}

        resp = requests.post(
            self.auth_server_token_url,
            params=params,
            headers=headers
        )
        if resp.status_code != 200:
            self.logger.error({
                'message': f'Auth-token request failed with status {resp.status_code}',
                **locals()
            })
            self._access_token = None
        else:
            data = resp.json()
            self.logger.info(**locals())
            self._access_token = data['access_token']

    # just send get request
    def _send_get(self, url, *args, **kwargs):
        return requests.get(
            url=url,
            *args,
            **kwargs
        )

    # just send post request
    def _send_post(self, url, *args, **kwargs):
        return requests.post(
            url=url,
            *args,
            **kwargs
        )

    # cast a string token to Bearer Authorization header type
    def make_bearer_token_header(self, token):
        return 'Bearer ' + token

    # sends get request with oauth workaround
    def get(self, url, authorization_required=True, *args, **kwargs):
        self.logger.info(f'Entering get {url}')
        if not authorization_required:
            return self._send_get(url, *args, **kwargs)

        headers = kwargs.get('headers', {})
        headers['Authorization'] = self.make_bearer_token_header(self._access_token)

        super_kwargs = dict(kwargs, headers=headers)

        resp = requests.get(
            url,
            *args,
            **super_kwargs
        )

        # if access_token is None or expired (sorry for next) - in fact it will bu run each time
        if resp.status_code == 403:
            self.logger.info('refresh token')
            self._refresh_token()
            super_kwargs['headers']['Authorization'] = self.make_bearer_token_header(self._access_token)

            resp = requests.get(
                url,
                *args,
                **super_kwargs
            )
        self.logger.info(**locals())
        return resp
