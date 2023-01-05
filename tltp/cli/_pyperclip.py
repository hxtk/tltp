import sys

_MESSAGE = """
The clipboard feature requires the optional dependency `pyperclip`.
You may install it by running the following command or your platform's
equivalent:
    $ pip install pyperclip
"""


def copy(_: str):
    print(_MESSAGE, file=sys.stderr)
    exit(1)
