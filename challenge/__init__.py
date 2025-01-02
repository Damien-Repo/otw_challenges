import re
import requests

from bs4 import BeautifulSoup as BS


class Challenge():

    NAME = None                       # Must be defined by subclass

    DOC_URL = None                    # Must be defined by subclass
    DOC_XML_NODE_ID = 'level-goal'

    CHALLENGE_PASS_FILENAME = None    # Must be defined by subclass

    PASSWD_LENGTH = 32
    PASSWD_PATTERN = f'[a-zA-z0-9]{{{PASSWD_LENGTH}}}'
    PASSWD_ALL_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    def __init__(self, passwd):
        assert(self.NAME is not None)
        assert(self.DOC_URL is not None)
        assert(self.CHALLENGE_PASS_FILENAME is not None)

        self.name = self.__class__.__name__.lower()
        self._id = int(re.search('([0-9]+)$', self.name).group(0))
        self._passwd = passwd

        self.doc_webpage_soup = None

        self.log()
        self.log(f'=== Challenge {self.name.capitalize()} ({self.doc_url}) ===')

    @property
    def next_pass_filename(self):
        return self.CHALLENGE_PASS_FILENAME % (self._id + 1)

    @property
    def passwd(self):
        return self._passwd

    @property
    def doc_url(self):
        return self.DOC_URL % (self._id + 1)

    def log(self, message='', **kwargs):
        if message is None:
            print(**kwargs)
            return

        print(f'[#{self._id}] {message}', **kwargs)

    def manual_challenge(self, *procedure, password_to_find=None):
        self.log('')
        self.log('  ===== MANUAL CHALLENGE =====')
        self.log('    - How to proceed:')
        for i, line in enumerate(procedure):
            self.log(f'      - {i + 1}): {line}')

        if password_to_find is not None:
            return password_to_find

    def log_goals_and_cmds(self):
        try:
            webpage = requests.get(self.doc_url, timeout=5)
        except requests.Timeout:
            self.log(f'  - Error timeout to get "{self.doc_url}"')
            return None
        except requests.RequestException as e:
            self.log(f'  - Error to get "{self.doc_url}": {e}')
            return None

        self.doc_webpage_soup = BS(webpage.text, 'html.parser')
        goals = []
        try:
            for sibling in self.doc_webpage_soup.find('h2', id=self.DOC_XML_NODE_ID).find_next_siblings():
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
            cmds = self.doc_webpage_soup.find('h2', id='commands-you-may-need-to-solve-this-level').find_next_sibling().text
            cmds = cmds.replace('\n,\n', ', ').replace(',\n', ', ')

            if len(cmds) > 0:
                self.log(f'      | Usefull commands: {cmds}')
                self.log('      +-----------')

        except AttributeError:
            pass

    def process_challenge_prolog(self):
        pass

    def process_challenge(self):
        raise NotImplementedError

    def process_challenge_epilog(self):
        pass

    def run(self):
        self.log_goals_and_cmds()

        try:
            self.process_challenge_prolog()
            creds = self.process_challenge()
        finally:
            self.process_challenge_epilog()

        self.log()

        return creds
