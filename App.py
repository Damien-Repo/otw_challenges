#!/usr/bin/env python

import argparse
import sys

from games import all_games, Game

class App():
    def __init__(self, games_name):
        self._games = []

        if 'all' in games_name:
            games_name = all_games

        for game_name in games_name:
            self._games.append(Game(game_name))

    def run(self):
        for game in self._games:
            game.run_all_challenges()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('--games', '-g',
                        required=True,
                        help='Games to run',
                        dest='games_name',
                        choices=all_games + ['all'],
                        nargs='+',
                        type=str)

    args = parser.parse_args()

    params = vars(args)

    app = App(**params)
    app.run()
