from paramiko import SSHClient, AutoAddPolicy, ssh_exception

from . import Challenge


class ChallengeSSH(Challenge):

    SSH_URL = None      # Must be defined by subclass
    SSH_PORT = None     # Must be defined by subclass
    SSH_USER = None     # Must be defined by subclass

    SSH_CONNECTION_RETRY_COUNT_MAX = 3

    def __init__(self, *args, **kwargs):
        assert(self.SSH_URL is not None)
        assert(self.SSH_PORT is not None)
        assert(self.SSH_USER is not None)

        self._ssh_connections = []

        self._remote_work_dir = None

        super().__init__(*args, **kwargs)

    @property
    def ssh_user(self):
        return self.SSH_USER % (self._id)

    @property
    def ssh_user_next(self):
        return self.SSH_USER % (self._id + 1)

    @property
    def ssh_client(self):
        assert len(self._ssh_connections) == 1
        return self._ssh_connections[0]

    def create_remote_work_dir(self):
        return self.exec_cmd('mktemp -d')[0][0].strip()

    @property
    def remote_work_dir(self):
        if self._remote_work_dir is None:
            work_dir = self.create_remote_work_dir()
            self.log(f'      - <work_dir> => {work_dir}')
            self._remote_work_dir = work_dir

        return self._remote_work_dir

    def log(self, message='', **kwargs):
        if self._remote_work_dir is not None:
            message = message.replace(self._remote_work_dir, '<work_dir>')

        super().log(message, **kwargs)

    def make_ssh_client(self):
        self.log(f'  - Connect: ssh -p {self.SSH_PORT} {self.ssh_user}@{self.SSH_URL}')

        ssh = SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        connect_params = {
            'port': self.SSH_PORT,
            'username': self.ssh_user,
            'password': self._passwd,
            'allow_agent': False,
            'timeout': 10.0,
            'banner_timeout': 10.0,
        }

        retry_count = 0
        while retry_count < self.SSH_CONNECTION_RETRY_COUNT_MAX:
            try:
                ssh.connect(self.SSH_URL, **connect_params)
                break
            except ssh_exception.SSHException:
                retry_count += 1
                self.log(f'Connection error, retrying #{retry_count}...')

        self._ssh_connections.append(ssh)

        return ssh

    def _close_all_ssh_client(self):
        for ssh in self._ssh_connections:
            ssh.close()

    def get_ssh_session(self, ssh=None):
        if ssh is None:
            ssh = self.ssh_client

        t = ssh.get_transport()
        return t.open_session()

    def _exec_cmd(self, cmd, ssh=None, quiet=False, timeout=5.0):
        if ssh is None:
            ssh = self.ssh_client

        if not quiet:
            self.log(f'    - Exec command $> {cmd}')

        return ssh.exec_command(cmd, get_pty=True, timeout=timeout)

    def exec_cmd_raw(self, *args, **kwargs):
        return self._exec_cmd(*args, **kwargs)

    def exec_cmd(self, *args, **kwargs):
        _, stdout, stderr = self.exec_cmd_raw(*args, **kwargs)
        return (stdout.readlines(), stderr.readlines())

    def process_challenge_prolog(self):
        self.make_ssh_client()

    def process_challenge(self):
        raise NotImplementedError

    def process_challenge_epilog(self):
        self._close_all_ssh_client()
