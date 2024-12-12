
import os
import json
import re
import importlib
import paramiko

all_games = [f for f in os.listdir(os.path.dirname(__file__)) if not f.startswith('.') and not f.startswith('_') and not f.endswith('.py')]

class Game():

    CREDENTIALS_DIR = 'credentials'

    CHALLENGES_COUNT_MAX = 50

    def __init__(self, game_name):
        assert(game_name in all_games)
        self._name = game_name

        # By default the credentials for the first challenge is dummy0:dummy0
        self._credentials = {
            f'{self._name}0': f'{self._name}0'
        }

        self._creds_filename = os.path.join(self.CREDENTIALS_DIR, self._name)

        os.makedirs(self.CREDENTIALS_DIR, exist_ok=True)
        if os.path.exists(self._creds_filename):
            with open(self._creds_filename, 'r', encoding='utf-8') as f:
                self._credentials = json.load(f)

    def _run_challenge(self, challenge_module_name, challenge_name, next_challenge_name):
        try:
            module_full_name = f'{os.path.dirname(__file__).split(os.path.sep)[-1]}.{self._name}.{challenge_module_name}'
            module = importlib.import_module(module_full_name)
        except ModuleNotFoundError as e:
            print(f'Cannot load module "{module_full_name}": {e}')
            return False

        challenge_class = getattr(module, challenge_module_name)
        challenge = challenge_class(self._credentials[challenge_name])

        if next_challenge_name not in self._credentials or len(self._credentials[next_challenge_name]) == 0:
            try:
                passwd = challenge.run()
                assert passwd is not None, 'Password not found'
                assert re.match('[a-zA-Z0-9]{32}', passwd), 'Password is not valid'

                self._credentials[next_challenge_name] = passwd

            except paramiko.ssh_exception.AuthenticationException as e:
                print(f'Connection error: {e}')
                return False

            except NotImplementedError:
                print('Challenge not yet implemented')
                return False

            except StopIteration:
                print('\n###########################################################')
                print('### Congratulations all challenges passed successfuly ! ###')
                print('###########################################################')
                return False

        return True

    def run_all_challenges(self):
        for i in range(0, self.CHALLENGES_COUNT_MAX):
            challenge_module_name = f'{self._name.capitalize()}_{i:02}'

            challenge_name = f'{self._name}{i}'
            next_challenge_name = f'{self._name}{i + 1}'

            if not self._run_challenge(challenge_module_name, challenge_name, next_challenge_name):
                break

            print(f'     *** {next_challenge_name} => {self._credentials[next_challenge_name]} ***')

            with open(self._creds_filename, 'w', encoding='utf-8') as f:
                json.dump(self._credentials, f)
