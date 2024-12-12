#!/usr/bin/env python

import argparse
import sys

from games import all_games, Game

class App():
    def __init__(self, game_name):
        self._game = Game(game_name)

    def run(self):
        self._game.run_all_challenges()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('--game', '-g',
                        help='Game to run',
                        dest='game_name',
                        choices=all_games,
                        type=str)

    args = parser.parse_args()

    params = vars(args)

    app = App(**params)
    app.run()
