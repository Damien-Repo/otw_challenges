

from paramiko import SSHClient, AutoAddPolicy
from bs4 import BeautifulSoup as BS

import requests
import re


class Challenge():

    NAME = None         # Must be defined by subclass

    WEB_URL = None      # Must be defined by subclass

    SSH_URL = None      # Must be defined by subclass
    SSH_PORT = None     # Must be defined by subclass
    SSH_USER = None     # Must be defined by subclass

    CHALLENGE_PASS_FILENAME = None  # Must be defined by subclass

    PASSWD_LENGTH = 32
    PASSWD_PATTERN = f'[a-zA-z0-9]{{{PASSWD_LENGTH}}}'
    PASSWD_ALL_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    def __init__(self, passwd):
        assert(self.NAME is not None)
        assert(self.WEB_URL is not None)
        assert(self.SSH_URL is not None)
        assert(self.SSH_PORT is not None)
        assert(self.SSH_USER is not None)
        assert(self.CHALLENGE_PASS_FILENAME is not None)

        self.name = self.__class__.__name__.lower()
        self._id = int(re.search('([0-9]+)$', self.name).group(0))
        self._passwd = passwd

        self.url = self.WEB_URL % (self._id + 1)
        self.webpage = None

        self._ssh_connections = []

        self._remote_work_dir = None

        self.log()
        self.log(f'=== Challenge {self.name.capitalize()} ({self.url}) ===')

    @property
    def remote_work_dir(self):
        if self._remote_work_dir is None:
            work_dir = self.exec_cmd('mktemp -d')[0][0].strip()
            self.log(f'      - <work_dir> => {work_dir}')
            self._remote_work_dir = work_dir
        return self._remote_work_dir

    @property
    def next_banditpass_filename(self):
        return self.CHALLENGE_PASS_FILENAME % (self._id + 1)

    @property
    def passwd(self):
        return self._passwd

    @property
    def ssh_user(self):
        return self.SSH_USER % (self._id)

    @property
    def ssh_client(self):
        assert len(self._ssh_connections) == 1
        return self._ssh_connections[0]

    def make_ssh_client(self):
        self.log(f'  - Connect: ssh -p {self.SSH_PORT} {self.ssh_user}@{self.SSH_URL}')

        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        ssh.connect(self.SSH_URL, port=self.SSH_PORT, username=self.ssh_user, password=self._passwd, allow_agent=False, timeout=10.0, banner_timeout=10.0)

        self._ssh_connections.append(ssh)

        return ssh

    def _close_all_ssh_client(self):
        for ssh in self._ssh_connections:
            ssh.close()

    def get_ssh_session(self, ssh=None):
        if ssh is None:
            assert len(self._ssh_connections) > 0
            ssh = self._ssh_connections[0]

        t = ssh.get_transport()
        return t.open_session()

    def log(self, message=None, **kwargs):
        if message is None:
            print(**kwargs)
            return

        if self._remote_work_dir is not None:
            message = message.replace(self._remote_work_dir, '<work_dir>')

        print(f'[#{self._id}] {message}', **kwargs)

    def manual_challenge(self, *procedure, password_to_find=None):
        self.log('')
        self.log('  ===== MANUAL CHALLENGE =====')
        self.log('    - How to proceed:')
        for i, line in enumerate(procedure):
            self.log(f'      - {i + 1}): {line}')

        if password_to_find is not None:
            return password_to_find

    def _exec_cmd(self, ssh, cmd):
        self.log(f'    - Exec command $> {cmd}')
        return ssh.exec_command(cmd, get_pty=True, timeout=10.0)

    def exec_cmd(self, cmd, ssh=None):
        if ssh is None:
            assert len(self._ssh_connections) > 0
            ssh = self._ssh_connections[0]

        _, stdout, stderr = self._exec_cmd(ssh, cmd)
        return (stdout.readlines(), stderr.readlines())

    def exec_cmd_raw(self, cmd, ssh=None):
        if ssh is None:
            assert len(self._ssh_connections) > 0
            ssh = self._ssh_connections[0]

        return self._exec_cmd(ssh, cmd)

    def log_goals_and_cmds(self):
        try:
            webpage = requests.get(self.url, timeout=5)
        except requests.Timeout:
            self.log(f'  - Error timeout to get "{self.url}"')
            return None
        except requests.RequestException as e:
            self.log(f'  - Error to get "{self.url}": {e}')
            return None

        soup = BS(webpage.text, 'html.parser')
        goals = []
        try:
            for sibling in soup.find('h2', id='level-goal').find_next_siblings():
                if sibling.name == 'h2':
                    break
                if sibling.name == 'ul':
                    goals += sibling.text.split('\n')
                    continue
                goals.append(sibling.text.replace('\n', ' '))

            if len(goals) > 0:
                self.log('      +-----------')
                for goal in goals:
                    goal_arr = goal.split(' ')
                    for i in range(0, len(goal_arr), 20):
                        self.log(f'      | {" ".join(goal_arr[i:i+20])}')
                self.log('      +-----------')

        except AttributeError:
            pass

        try:
            cmds = soup.find('h2', id='commands-you-may-need-to-solve-this-level').find_next_sibling().text
            cmds = cmds.replace('\n,\n', ', ').replace(',\n', ', ')

            if len(cmds) > 0:
                self.log(f'      | Usefull commands: {cmds}')
                self.log('      +-----------')

        except AttributeError:
            pass

    def run(self):
        self.log_goals_and_cmds()

        try:
            self.make_ssh_client()
            creds = self.process_challenge()
        finally:
            self._close_all_ssh_client()

        self.log()

        return creds

    def process_challenge(self):
        raise NotImplementedError

